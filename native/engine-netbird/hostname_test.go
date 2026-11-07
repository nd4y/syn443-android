package netbird

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/embed"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/sagernet/sing-box/adapter"
)

func TestDefaultHostnameSatisfiesManagementValidatorAndPreservesSDKIdentity(t *testing.T) {
	if _, e := nbdns.GetParsedDomainLabel(""); e == nil {
		t.Fatal("pinned management validator unexpectedly accepts missing hostname")
	}
	dir := t.TempDir()
	config := []byte(`{"PrivateKey":"synthetic-wireguard-material","SSHKey":"synthetic-ssh-material"}`)
	if e := os.WriteFile(filepath.Join(dir, "config.json"), config, 0600); e != nil {
		t.Fatal(e)
	}
	name, e := peerHostname(dir, "", "")
	if e != nil || !localHostname.MatchString(name) {
		t.Fatal("default", name, e)
	}
	if label, e := nbdns.GetParsedDomainLabel(name); e != nil || label != name {
		t.Fatal("management rejects default", e)
	}
	again, e := peerHostname(dir, "", "")
	if e != nil || again != name {
		t.Fatal("restart renamed identity", e)
	}
	stored, e := os.ReadFile(filepath.Join(dir, "config.json"))
	if e != nil || string(stored) != string(config) {
		t.Fatal("hostname changed SDK key material", e)
	}
	info, e := os.Stat(filepath.Join(dir, "syn443-hostname"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("metadata permissions", e)
	}
	other, e := peerHostname(t.TempDir(), "", "")
	if e != nil || other == name {
		t.Fatal("distinct local identities collide", e)
	}
	custom, e := peerHostname(dir, "", "Operator chosen name")
	if e != nil || custom != "Operator chosen name" {
		t.Fatal("explicit name overwritten")
	}
	if again, e := peerHostname(dir, "", ""); e != nil || again != name {
		t.Fatal("explicit override changed fallback state")
	}
}

func TestManagedHostnameIsScopedStableAndDoesNotCreateLocalMetadata(t *testing.T) {
	dir, namespace := managedTestDirectory(t)
	name, e := peerHostname(dir, namespace, "")
	if e != nil || !localHostname.MatchString(name) {
		t.Fatal(e)
	}
	if e = os.Remove(dir); e != nil {
		t.Fatal(e)
	}
	// No SDK/file IO or physical network is necessary for a managed default.
	again, e := peerHostname(dir, namespace, "")
	if e != nil || again != name {
		t.Fatal("managed fallback changed", e)
	}
	t.Run("other-identity", func(t *testing.T) {
		otherDir, otherNamespace := managedTestDirectory(t)
		other, e := peerHostname(otherDir, otherNamespace, "")
		if e != nil || other == name {
			t.Fatal("foreign managed identity shares label", e)
		}
	})
	for _, bad := range []string{"managed-netbird/short", "other/namespace", namespace + "/child"} {
		if _, e := peerHostname(dir, bad, ""); !errors.Is(e, errPeerHostname) {
			t.Fatal("invalid namespace admitted", bad, e)
		}
	}
}

func TestHostnameMetadataDamageOrLinksCannotReachSDKOrOverwriteFiles(t *testing.T) {
	for _, kind := range []string{"oversized", "malformed", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "syn443-hostname")
			switch kind {
			case "oversized":
				if e := os.WriteFile(path, []byte(strings.Repeat("x", 4096)), 0600); e != nil {
					t.Fatal(e)
				}
			case "malformed":
				if e := os.WriteFile(path, []byte(strings.Repeat("x", 39)), 0600); e != nil {
					t.Fatal(e)
				}
			case "directory":
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				target := filepath.Join(t.TempDir(), "foreign")
				if e := os.WriteFile(target, []byte("foreign-metadata"), 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(target, path); e != nil {
					t.Fatal(e)
				}
			}
			before, e := os.Lstat(path)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = peerHostname(dir, "", ""); !errors.Is(e, errPeerHostname) {
				t.Fatal("unsafe metadata accepted", e)
			}
			after, e := os.Lstat(path)
			if e != nil || !os.SameFile(before, after) || before.Size() != after.Size() {
				t.Fatal("unsafe metadata replaced", e)
			}
		})
	}
	if _, e := peerHostname(filepath.Join(t.TempDir(), "missing"), "", ""); !errors.Is(e, errPeerHostname) {
		t.Fatal("missing unowned directory created", e)
	}
}

func TestSDKReceivesValidDefaultHostnameWithNoUserInput(t *testing.T) {
	d := deferredFixture(t)
	d.current.newClient = func(opts embed.Options) (peerClient, error) {
		if opts.DeviceName == "" {
			t.Fatal("empty hostname reached actual SDK boundary")
		}
		if label, e := nbdns.GetParsedDomainLabel(opts.DeviceName); e != nil || label != opts.DeviceName {
			t.Fatal("management hostname contract", e)
		}
		return &rejectedPeer{}, nil
	}
	if e := d.Start(adapter.StartStateStarted); e != nil {
		t.Fatal(e)
	}
	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("startup did not finish")
	}
	if e := d.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestInvalidLocalHostnameRequiresActionBeforeAnySDKNetworkAttempt(t *testing.T) {
	d := deferredFixture(t)
	if e := os.WriteFile(filepath.Join(d.options.StateDirectory, "syn443-hostname"), []byte("corrupted"), 0600); e != nil {
		t.Fatal(e)
	}
	d.current.newClient = func(embed.Options) (peerClient, error) {
		t.Error("invalid metadata reached SDK")
		return nil, errors.New("forbidden")
	}
	d.makePeer = func() (*Outbound, error) { t.Error("metadata failure retried network"); return nil, context.Canceled }
	if e := d.Start(adapter.StartStateStarted); e != nil {
		t.Fatal(e)
	}
	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("invalid metadata kept retrying")
	}
	state := d.state.Load().(moduleState)
	if state.Phase != "NeedsAction" || state.Reason != "identity_metadata_unavailable" || state.Retry.Attempt != 0 {
		t.Fatal("metadata failure classification", state)
	}
	d.Close()
}
