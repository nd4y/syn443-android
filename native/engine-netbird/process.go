package netbird

import (
	"errors"
	"sync"
)

var peerProcess struct {
	sync.Mutex
	active bool
}

// Acquire before embed.New: upstream construction also changes process globals.
func acquirePeerProcess() (func(), error) {
	peerProcess.Lock()
	defer peerProcess.Unlock()
	if peerProcess.active {
		return nil, errors.New("only one NetBird client may run in this core process")
	}
	peerProcess.active = true
	var once sync.Once
	return func() { once.Do(func() { peerProcess.Lock(); peerProcess.active = false; peerProcess.Unlock() }) }, nil
}
