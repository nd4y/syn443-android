package netbird

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// The lock belongs to an open file descriptor, not a PID/stale sentinel file.
// OS process termination releases it without deleting another client's state.
func acquireIdentity(directory string) (func(), error) {
	file, err := os.OpenFile(filepath.Join(directory, "identity.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := lockIdentity(file); err != nil {
		file.Close()
		return nil, fmt.Errorf("netbird identity is already in use or cannot be locked: %w", err)
	}
	var once sync.Once
	return func() { once.Do(func() { _ = unlockIdentity(file); _ = file.Close() }) }, nil
}
