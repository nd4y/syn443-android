//go:build unix

package netbird

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockIdentity(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

func unlockIdentity(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
