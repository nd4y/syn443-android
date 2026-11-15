package netbird

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"golang.org/x/crypto/ssh"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func managedTestDirectory(t *testing.T) (string, string) {
	t.Helper()
	sum := sha256.Sum256([]byte(t.Name()))
	namespace := "managed-netbird/" + base64.RawURLEncoding.EncodeToString(sum[:])
	directory := filepath.Join(t.TempDir(), filepath.FromSlash(namespace))
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory, namespace
}

func writeManagedTestKeys(t *testing.T, directory string) []byte {
	t.Helper()
	wg, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "synthetic test identity")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"PrivateKey": wg.String(), "SSHKey": string(pem.EncodeToMemory(block)), "ManagementURL": "https://mesh.example.invalid:443", "UnrelatedSetting": true})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "config.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestManagedIdentitySealsBeforeEnrollmentAndReusesDurableKeys(t *testing.T) {
	dir, namespace := managedTestDirectory(t)
	identity, err := prepareManagedIdentity(dir, namespace)
	if err != nil || identity.manifest.Initialized {
		t.Fatal("fresh reservation", err)
	}
	keys := writeManagedTestKeys(t, dir)
	evidence, err := identity.seal()
	if err != nil || !managedDigest(evidence) {
		t.Fatal("durable identity", err)
	}
	for range 3 {
		reopened, err := prepareManagedIdentity(dir, namespace)
		if err != nil || reopened.expected != evidence || !reopened.manifest.Initialized {
			t.Fatal("identity changed on reopen", err)
		}
		again, err := reopened.seal()
		if err != nil || again != evidence {
			t.Fatal("identity changed on reseal", err)
		}
	}
	actual, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil || string(actual) != string(keys) {
		t.Fatal("SDK settings rewritten", err)
	}
	manifest, _ := os.ReadFile(filepath.Join(dir, managedManifestName))
	if strings.Contains(string(manifest), "PrivateKey") || strings.Contains(string(manifest), "SSHKey") {
		t.Fatal("private material in manifest")
	}
}

func TestManagedIdentityRecoversInterruptedOfflineKeyCreationWithoutRotation(t *testing.T) {
	dir, namespace := managedTestDirectory(t)
	if _, err := prepareManagedIdentity(dir, namespace); err != nil {
		t.Fatal(err)
	}
	writeManagedTestKeys(t, dir)
	before, err := managedConfigEvidence(dir, namespace, false)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := prepareManagedIdentity(dir, namespace)
	if err != nil || recovered.expected != before || recovered.manifest.Initialized {
		t.Fatal("offline construction cannot resume", err)
	}
	if proof, err := recovered.seal(); err != nil || proof != before {
		t.Fatal("interrupted identity replaced", err)
	}
}

func TestManagedPinnedSDKConstructorPersistsKeysWithoutEnrollment(t *testing.T) {
	dir, namespace := managedTestDirectory(t)
	release, err := acquirePeerProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// New changes these process globals even though it must not perform login.
	for _, name := range []string{netstack.EnvUseNetstackMode, netstack.EnvSkipProxy, "NB_DNS_STATE_FILE"} {
		t.Setenv(name, os.Getenv(name))
	}
	identity, err := prepareManagedIdentity(dir, namespace)
	if err != nil {
		t.Fatal(err)
	}
	setup := "synthetic-offline-setup"
	checkGrantAbsent := func() {
		t.Helper()
		err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Type().IsRegular() {
				t.Fatal("unexpected SDK state entry")
			}
			data, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			if len(data) > 65536 || bytes.Contains(data, []byte(setup)) || bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString([]byte(setup)))) {
				t.Fatal("offline SDK state retained setup material or exceeded its bound")
			}
			return nil
		})
		if err != nil {
			t.Fatal("SDK state inspection failed", err)
		}
	}
	client, err := embed.New(embed.Options{SetupKey: setup, ManagementURL: "https://mesh.example.invalid", ConfigPath: filepath.Join(dir, "config.json"), StatePath: filepath.Join(dir, "state.json"), BlockInbound: true, DisableIPv6: true})
	if err != nil {
		t.Fatal("pinned SDK offline constructor", err)
	}
	if err = client.Stop(context.Background()); !errors.Is(err, embed.ErrClientNotStarted) {
		t.Fatal("constructor unexpectedly started a peer", err)
	}
	evidence, err := identity.seal()
	if err != nil {
		t.Fatal("pinned SDK config incompatible with ownership fence", err)
	}
	checkGrantAbsent()
	reopened, err := prepareManagedIdentity(dir, namespace)
	if err != nil || reopened.expected != evidence {
		t.Fatal("pinned SDK durable identity cannot resume", err)
	}
	// Empty setup key is allowed only for an existing, independently checked SDK
	// config. New must retain both private keys before any subsequent Start.
	client, err = embed.New(embed.Options{ManagementURL: "https://mesh.example.invalid", ConfigPath: filepath.Join(dir, "config.json"), StatePath: filepath.Join(dir, "state.json"), BlockInbound: true, DisableIPv6: true})
	if err != nil {
		t.Fatal("keyless reopen rejected", err)
	}
	if err = client.Stop(context.Background()); !errors.Is(err, embed.ErrClientNotStarted) {
		t.Fatal(err)
	}
	if again, err := reopened.seal(); err != nil || again != evidence {
		t.Fatal("pinned SDK reopen rotated private keys", err)
	}
	checkGrantAbsent()
}

func TestManagedIdentityNeverAdoptsOrRegeneratesEstablishedState(t *testing.T) {
	for _, damage := range []string{"unowned", "missing", "changed", "broken", "symlink", "publicPermissions", "missingManifest"} {
		t.Run(damage, func(t *testing.T) {
			dir, namespace := managedTestDirectory(t)
			if damage == "unowned" {
				writeManagedTestKeys(t, dir)
			} else {
				identity, err := prepareManagedIdentity(dir, namespace)
				if err != nil {
					t.Fatal(err)
				}
				original := writeManagedTestKeys(t, dir)
				if _, err = identity.seal(); err != nil {
					t.Fatal(err)
				}
				config := filepath.Join(dir, "config.json")
				switch damage {
				case "missing":
					if err = os.Remove(config); err != nil {
						t.Fatal(err)
					}
				case "changed":
					writeManagedTestKeys(t, dir)
				case "broken":
					if err = os.WriteFile(config, []byte(`{"PrivateKey":null}`), 0600); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					other := filepath.Join(t.TempDir(), "foreign.json")
					if err = os.WriteFile(other, original, 0600); err != nil {
						t.Fatal(err)
					}
					if err = os.Remove(config); err != nil {
						t.Fatal(err)
					}
					if err = os.Symlink(other, config); err != nil {
						t.Fatal(err)
					}
				case "publicPermissions":
					if err = os.Chmod(config, 0644); err != nil {
						t.Fatal(err)
					}
				case "missingManifest":
					if err = os.Remove(filepath.Join(dir, managedManifestName)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := prepareManagedIdentity(dir, namespace); !errors.Is(err, errManagedIdentity) {
				t.Fatal("damaged identity admitted", err)
			}
		})
	}
}

func TestManagedManifestAndConfigRejectAmbiguousOrUnboundedData(t *testing.T) {
	dir, namespace := managedTestDirectory(t)
	identity, err := prepareManagedIdentity(dir, namespace)
	if err != nil {
		t.Fatal(err)
	}
	valid := writeManagedTestKeys(t, dir)
	for _, bad := range []string{`null`, `[]`, `{}`, `{"PrivateKey":"x","PrivateKey":"y","SSHKey":"z"}`, string(valid) + ` {}`, strings.Repeat("x", (256<<10)+1)} {
		if err = os.WriteFile(filepath.Join(dir, "config.json"), []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = identity.seal(); err == nil {
			t.Fatal("invalid config sealed")
		}
	}
	if err = os.WriteFile(filepath.Join(dir, "config.json"), valid, 0600); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(dir, managedManifestName))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`null`, `{}`, string(manifest) + "\n", strings.TrimSuffix(string(manifest), "}") + `,"extra":true}`, strings.Replace(string(manifest), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1), strings.Replace(string(manifest), namespace, "managed-netbird/foreign", 1), strings.Repeat("x", 1025)} {
		if err = os.WriteFile(filepath.Join(dir, managedManifestName), []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = prepareManagedIdentity(dir, namespace); err == nil {
			t.Fatal("invalid manifest accepted")
		}
	}
}

func TestManagedNamespaceCannotAliasOperatorParentOrAnotherIdentity(t *testing.T) {
	dir, namespace := managedTestDirectory(t)
	for _, bad := range []struct{ directory, namespace string }{
		{dir, "netbird/legacy"}, {dir, namespace + "="}, {dir, namespace[:len(namespace)-1] + "B"}, {filepath.Join(dir, ".."), namespace}, {filepath.Dir(dir), namespace}, {"relative/" + namespace, namespace},
	} {
		if validateManagedDirectory(bad.directory, bad.namespace) == nil {
			t.Fatal("path alias accepted")
		}
	}
	parent := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(dir), parent); err != nil {
		t.Fatal(err)
	}
	aliasRoot := filepath.Join(t.TempDir(), "managed-netbird")
	if err := os.Symlink(parent, aliasRoot); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(aliasRoot, filepath.Base(dir))
	if validateManagedDirectory(alias, namespace) == nil || validateManagedParents(alias, namespace) == nil {
		t.Fatal("parent symlink adopted")
	}
	if _, err := prepareManagedIdentity(dir, namespace); err != nil {
		t.Fatal(err)
	}
	writeManagedTestKeys(t, dir)
	identity, err := prepareManagedIdentity(dir, namespace)
	if err != nil {
		t.Fatal(err)
	}
	writeManagedTestKeys(t, dir)
	if _, err = identity.seal(); err == nil {
		t.Fatal("SDK constructor changed prepared keys")
	}
}

type managedTestPeer struct {
	peerClient
	snapshot embed.ConnectionSnapshot
	start    func(context.Context) error
	stops    atomic.Int32
}

func (p *managedTestPeer) Start(ctx context.Context) error                          { return p.start(ctx) }
func (p *managedTestPeer) Stop(context.Context) error                               { p.stops.Add(1); return nil }
func (p *managedTestPeer) ConnectionSnapshot() embed.ConnectionSnapshot             { return p.snapshot }
func (p *managedTestPeer) ProbePeer(context.Context, string) (time.Duration, error) { return 0, nil }
func (p *managedTestPeer) NotifyNetworkChange()                                     {}

type managedBlockedPeer struct {
	managedTestPeer
	entered, release chan struct{}
}

func (p *managedBlockedPeer) ConnectionSnapshot() embed.ConnectionSnapshot {
	close(p.entered)
	<-p.release
	return p.snapshot
}

func TestManagedStartSealsKeysBeforeNetworkAndRejectsCorruptionBeforeSDK(t *testing.T) {
	dir, namespace := managedTestDirectory(t)
	var expected string
	for attempt := 0; attempt < 2; attempt++ {
		peer := &managedTestPeer{snapshot: embed.ConnectionSnapshot{ManagementConnected: true, SignalConnected: true, IP: "198.51.100.7/24"}}
		peer.start = func(context.Context) error {
			manifest, err := readManagedManifest(dir)
			if err != nil || !manifest.Initialized {
				t.Fatal("network before durable keys", err)
			}
			if expected != "" && expected != manifest.IdentityEvidence {
				t.Fatal("restart rotated identity")
			}
			expected = manifest.IdentityEvidence
			return nil
		}
		o := &Outbound{ctx: context.Background(), logger: logger.NOP(), manager: fakeManager{}, options: OutboundOptions{ConnectionMode: "vless", StateDirectory: dir, ManagedNamespace: namespace, SetupKey: "synthetic-setup", DialerOptions: option.DialerOptions{Detour: "vless"}}}
		o.newClient = func(opts embed.Options) (peerClient, error) {
			if attempt == 0 {
				writeManagedTestKeys(t, dir)
			} else if opts.SetupKey != "" {
				t.Fatal("setup secret retained on restart")
			}
			return peer, nil
		}
		if attempt == 1 {
			o.options.SetupKey = ""
		}
		if err := o.Start(adapter.StartStateStarted); err != nil {
			t.Fatal(err)
		}
		var proof managedRegistrationProof
		if json.Unmarshal([]byte(ManagedRegistrationProof()), &proof) != nil || proof.Namespace != namespace || proof.IdentityEvidence != expected {
			t.Fatal("registered native owner not proven")
		}
		for _, snapshot := range []embed.ConnectionSnapshot{{SignalConnected: true, IP: "198.51.100.7"}, {ManagementConnected: true, IP: "198.51.100.7"}, {ManagementConnected: true, SignalConnected: true, IP: "127.0.0.1"}, {ManagementConnected: true, SignalConnected: true, IP: "0.0.0.0"}, {ManagementConnected: true, SignalConnected: true, IP: "not an IP"}} {
			peer.snapshot = snapshot
			if ManagedRegistrationProof() != "{}" {
				t.Fatal("incomplete registration accepted")
			}
		}
		if err := o.Close(); err != nil {
			t.Fatal(err)
		}
		if ManagedRegistrationProof() != "{}" || peer.stops.Load() != 1 {
			t.Fatal("closed SDK owner retained proof")
		}
	}
	if err := os.Remove(filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
	o := &Outbound{ctx: context.Background(), logger: logger.NOP(), manager: fakeManager{}, options: OutboundOptions{ConnectionMode: "vless", StateDirectory: dir, ManagedNamespace: namespace, SetupKey: "synthetic-setup", DialerOptions: option.DialerOptions{Detour: "vless"}}, newClient: func(embed.Options) (peerClient, error) { t.Fatal("damaged identity reached SDK"); return nil, nil }}
	if err := o.Start(adapter.StartStateStarted); !errors.Is(err, errManagedIdentity) {
		t.Fatal("missing established keys admitted", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedRecoveryUsesOnlySealedExistingKeysAndNeverCarriesSetupMaterial(t *testing.T) {
	for _, scenario := range []string{"sealed", "unsealed", "missing-manifest", "corrupt-config"} {
		t.Run(scenario, func(t *testing.T) {
			dir, namespace := managedTestDirectory(t)
			identity, err := prepareManagedIdentity(dir, namespace)
			if err != nil {
				t.Fatal(err)
			}
			keys := writeManagedTestKeys(t, dir)
			if scenario != "unsealed" {
				if _, err = identity.seal(); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "missing-manifest" {
				if err = os.Remove(filepath.Join(dir, managedManifestName)); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "corrupt-config" {
				keys = []byte(`{"invalid":true}`)
				if err = os.WriteFile(filepath.Join(dir, "config.json"), keys, 0600); err != nil {
					t.Fatal(err)
				}
			}
			constructors := 0
			peer := &managedTestPeer{snapshot: embed.ConnectionSnapshot{ManagementConnected: true, SignalConnected: true, IP: "198.51.100.7/24"}, start: func(context.Context) error { return nil }}
			o := &Outbound{ctx: context.Background(), logger: logger.NOP(), manager: fakeManager{}, options: OutboundOptions{ConnectionMode: "vless", StateDirectory: dir, ManagedNamespace: namespace, RecoverExisting: true, DialerOptions: option.DialerOptions{Detour: "vless"}}}
			o.newClient = func(opts embed.Options) (peerClient, error) {
				constructors++
				if opts.SetupKey != "" || opts.JWTToken != "" || opts.ConfigPath != filepath.Join(dir, "config.json") {
					t.Fatal("recovery received enrollment credentials or another identity")
				}
				return peer, nil
			}
			err = o.Start(adapter.StartStateStarted)
			if scenario == "sealed" {
				if err != nil || constructors != 1 || ManagedRegistrationProof() == "{}" {
					t.Fatal("sealed keyless recovery", err)
				}
			} else if !errors.Is(err, errManagedIdentity) || constructors != 0 {
				t.Fatal("unknown/damaged identity reached SDK", err)
			}
			if err = o.Close(); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(filepath.Join(dir, "config.json"))
			if err != nil || !bytes.Equal(keys, after) {
				t.Fatal("recovery regenerated private keys", err)
			}
			if scenario == "missing-manifest" {
				if _, err = os.Stat(filepath.Join(dir, managedManifestName)); !os.IsNotExist(err) {
					t.Fatal("recovery adopted an unclaimed identity")
				}
			}
		})
	}
}

func TestManagedRegistrationRejectsLateRecorderAfterStop(t *testing.T) {
	dir, namespace := managedTestDirectory(t)
	identity, err := prepareManagedIdentity(dir, namespace)
	if err != nil {
		t.Fatal(err)
	}
	writeManagedTestKeys(t, dir)
	evidence, err := identity.seal()
	if err != nil {
		t.Fatal(err)
	}
	peer := &managedBlockedPeer{managedTestPeer: managedTestPeer{snapshot: embed.ConnectionSnapshot{ManagementConnected: true, SignalConnected: true, IP: "198.51.100.7"}}, entered: make(chan struct{}), release: make(chan struct{})}
	o := &Outbound{client: peer, ready: true, options: OutboundOptions{ManagedNamespace: namespace}, identityEvidence: evidence}
	runtimePeer.Lock()
	runtimePeer.outbound = o
	runtimePeer.Unlock()
	defer func() {
		runtimePeer.Lock()
		if runtimePeer.outbound == o {
			runtimePeer.outbound = nil
		}
		runtimePeer.Unlock()
	}()
	result := make(chan string, 1)
	go func() { result <- ManagedRegistrationProof() }()
	select {
	case <-peer.entered:
	case <-time.After(time.Second):
		t.Fatal("recorder did not run")
	}
	o.mu.Lock()
	o.closed = true
	o.mu.Unlock()
	close(peer.release)
	select {
	case actual := <-result:
		if actual != "{}" {
			t.Fatal("late registration accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("proof did not finish")
	}
}
