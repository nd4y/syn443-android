package netbird

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var errManagedIdentity = errors.New("managed netbird identity unavailable")

const managedManifestName = "syn443-managed-identity.json"

// An immutable ownership fence, not a registration receipt. It is initialized
// and synced before SDK Start can contact management. Keep acquireIdentity held
// throughout prepare/seal/Start/Stop: an absent or corrupt established config
// must never reach the SDK's automatic private-key generation path.
type managedManifest struct {
	SchemaVersion    int    `json:"schemaVersion"`
	Namespace        string `json:"namespace"`
	Initialized      bool   `json:"initialized"`
	IdentityEvidence string `json:"identityEvidence"`
}

type managedIdentity struct {
	directory string
	manifest  managedManifest
	expected  string
}

func managedDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validateManagedDirectory(directory, namespace string) error {
	if validateManagedPath(directory, namespace) != nil {
		return errManagedIdentity
	}
	// Check both owned namespace components. The preceding application-storage
	// root comes from the controller: Android may itself alias /data/user/0.
	for path, depth := directory, 0; depth < 2; path, depth = filepath.Dir(path), depth+1 {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errManagedIdentity
		}
	}
	return nil
}

func validateManagedPath(directory, namespace string) error {
	parts := strings.Split(namespace, "/")
	if len(parts) != 2 || parts[0] != "managed-netbird" || !managedDigest(parts[1]) || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || filepath.Base(directory) != parts[1] || filepath.Base(filepath.Dir(directory)) != parts[0] {
		return errManagedIdentity
	}
	return nil
}

func validateManagedParents(directory, namespace string) error {
	if validateManagedPath(directory, namespace) != nil {
		return errManagedIdentity
	}
	for path, depth := directory, 0; depth < 2; path, depth = filepath.Dir(path), depth+1 {
		info, err := os.Lstat(path)
		if err != nil && !os.IsNotExist(err) || err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return errManagedIdentity
		}
	}
	root, err := os.Stat(filepath.Dir(filepath.Dir(directory)))
	if err != nil || !root.IsDir() {
		return errManagedIdentity
	}
	return nil
}

func readPrivateFile(path string, limit int64, syncData bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > limit {
		return nil, errManagedIdentity
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errManagedIdentity
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errManagedIdentity
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		clear(data)
		return nil, errManagedIdentity
	}
	if syncData && f.Sync() != nil {
		clear(data)
		return nil, errManagedIdentity
	}
	return data, nil
}

func readManagedManifest(directory string) (managedManifest, error) {
	var value managedManifest
	data, err := readPrivateFile(filepath.Join(directory, managedManifestName), 1024, false)
	if err != nil {
		return value, err
	}
	if json.Unmarshal(data, &value) != nil || value.SchemaVersion != 1 || value.Initialized != (value.IdentityEvidence != "") || value.Initialized && !managedDigest(value.IdentityEvidence) {
		return managedManifest{}, errManagedIdentity
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, data) {
		return managedManifest{}, errManagedIdentity
	}
	return value, nil
}

func syncManagedDirectory(directory string) error {
	f, err := os.Open(directory)
	if err != nil {
		return errManagedIdentity
	}
	defer f.Close()
	if f.Sync() != nil {
		return errManagedIdentity
	}
	return nil
}

func writeManagedManifest(directory string, value managedManifest) error {
	data, err := json.Marshal(value)
	if err != nil {
		return errManagedIdentity
	}
	f, err := os.CreateTemp(directory, ".managed-identity-*")
	if err != nil {
		return errManagedIdentity
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || os.Rename(name, filepath.Join(directory, managedManifestName)) != nil || syncManagedDirectory(directory) != nil {
		return errManagedIdentity
	}
	actual, err := readManagedManifest(directory)
	if err != nil || actual != value {
		return errManagedIdentity
	}
	return nil
}

// Config fields belong to the pinned SDK. Unknown settings are retained, but
// duplicate top-level fields, missing/invalid keys and huge files fail closed.
// Only public-key digests leave this function; no private-key text is returned.
func managedConfigEvidence(directory, namespace string, syncData bool) (string, error) {
	data, err := readPrivateFile(filepath.Join(directory, "config.json"), 256<<10, syncData)
	if err != nil {
		return "", err
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return "", errManagedIdentity
	}
	fields := make(map[string]json.RawMessage)
	defer func() {
		for _, raw := range fields {
			clear(raw)
		}
	}()
	for decoder.More() {
		name, err := decoder.Token()
		key, ok := name.(string)
		if err != nil || !ok || len(fields) >= 256 {
			return "", errManagedIdentity
		}
		if _, exists := fields[key]; exists {
			return "", errManagedIdentity
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return "", errManagedIdentity
		}
		fields[key] = raw
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return "", errManagedIdentity
	}
	if _, err := decoder.Token(); err != io.EOF {
		return "", errManagedIdentity
	}
	var wgText, sshText string
	if json.Unmarshal(fields["PrivateKey"], &wgText) != nil || json.Unmarshal(fields["SSHKey"], &sshText) != nil || len(wgText) != 44 || len(sshText) == 0 || len(sshText) > 16384 {
		return "", errManagedIdentity
	}
	wg, err := wgtypes.ParseKey(wgText)
	if err != nil || wg == (wgtypes.Key{}) || wg.String() != wgText {
		return "", errManagedIdentity
	}
	defer clear(wg[:])
	sshBytes := []byte(sshText)
	defer clear(sshBytes)
	signer, err := ssh.ParsePrivateKey(sshBytes)
	if err != nil {
		return "", errManagedIdentity
	}
	wgPublic := wg.PublicKey()
	hash := sha256.New()
	hash.Write([]byte("syn443-netbird-sdk-identity-v1\x00" + namespace + "\x00"))
	hash.Write(wgPublic[:])
	hash.Write(signer.PublicKey().Marshal())
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil)), nil
}

func prepareManagedIdentity(directory, namespace string) (*managedIdentity, error) {
	if validateManagedDirectory(directory, namespace) != nil {
		return nil, errManagedIdentity
	}
	manifest, err := readManagedManifest(directory)
	if os.IsNotExist(err) {
		// Never claim pre-existing SDK files, even with a valid setup key.
		entries, listErr := os.ReadDir(directory)
		if listErr != nil {
			return nil, errManagedIdentity
		}
		for _, entry := range entries {
			if entry.Name() != "identity.lock" && entry.Name() != "syn443-retry.json" {
				return nil, errManagedIdentity
			}
		}
		manifest = managedManifest{SchemaVersion: 1, Namespace: namespace}
		if writeManagedManifest(directory, manifest) != nil {
			return nil, errManagedIdentity
		}
	} else if err != nil || manifest.Namespace != namespace {
		return nil, errManagedIdentity
	}
	evidence, configErr := managedConfigEvidence(directory, namespace, false)
	if configErr != nil && (!os.IsNotExist(configErr) || manifest.Initialized) || manifest.Initialized && manifest.IdentityEvidence != evidence {
		return nil, errManagedIdentity
	}
	return &managedIdentity{directory: directory, manifest: manifest, expected: evidence}, nil
}

func (identity *managedIdentity) seal() (string, error) {
	actual, err := readManagedManifest(identity.directory)
	if err != nil || actual != identity.manifest {
		return "", errManagedIdentity
	}
	evidence, err := managedConfigEvidence(identity.directory, identity.manifest.Namespace, true)
	if err != nil || identity.expected != "" && identity.expected != evidence || syncManagedDirectory(identity.directory) != nil {
		return "", errManagedIdentity
	}
	actual.Initialized, actual.IdentityEvidence = true, evidence
	if writeManagedManifest(identity.directory, actual) != nil {
		return "", errManagedIdentity
	}
	return evidence, nil
}
