package netbird

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

var errPeerHostname = errors.New("netbird local hostname metadata unavailable")
var localHostname = regexp.MustCompile(`^syn443-[0-9a-f]{32}$`)

// Called while the SDK identity-directory lock is held. An empty embed DeviceName
// is an explicit empty context value, not the SDK's platform fallback. Management
// rejects that empty DNS label. Names contain no OS hostname or hardware ID.
func peerHostname(directory, namespace, configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	if namespace != "" {
		if validateManagedPath(directory, namespace) != nil {
			return "", errPeerHostname
		}
		sum := sha256.Sum256([]byte(namespace))
		return "syn443-" + hex.EncodeToString(sum[:16]), nil
	}
	path := filepath.Join(directory, "syn443-hostname")
	info, e := os.Lstat(path)
	if e == nil {
		if !info.Mode().IsRegular() || info.Size() != 39 {
			return "", errPeerHostname
		}
		file, err := os.Open(path)
		if err != nil {
			return "", errPeerHostname
		}
		defer file.Close()
		actual, err := file.Stat()
		if err != nil || !os.SameFile(info, actual) {
			return "", errPeerHostname
		}
		data, err := io.ReadAll(io.LimitReader(file, 40))
		if err != nil || !localHostname.Match(data) {
			return "", errPeerHostname
		}
		return string(data), nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return "", errPeerHostname
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return "", errPeerHostname
	}
	name := "syn443-" + hex.EncodeToString(nonce[:])
	temp, e := os.CreateTemp(directory, ".syn443-hostname-")
	if e != nil {
		return "", errPeerHostname
	}
	defer os.Remove(temp.Name())
	if _, e = temp.WriteString(name); e == nil {
		e = temp.Sync()
	}
	closeErr := temp.Close()
	if e != nil || closeErr != nil {
		return "", errPeerHostname
	}
	if e = os.Rename(temp.Name(), path); e != nil {
		return "", errPeerHostname
	}
	dir, e := os.Open(directory)
	if e != nil {
		return "", errPeerHostname
	}
	defer dir.Close()
	if e = dir.Sync(); e != nil {
		return "", errPeerHostname
	}
	return name, nil
}
