//go:build unix

package keystore

import "golang.org/x/sys/unix"

// lockMemory pins the buffer's pages so the master key never reaches swap.
// Best-effort: an mlock failure (e.g. RLIMIT_MEMLOCK) must not break custody.
func lockMemory(b []byte) {
	if len(b) > 0 {
		_ = unix.Mlock(b)
	}
}

func unlockMemory(b []byte) {
	if len(b) > 0 {
		_ = unix.Munlock(b)
	}
}
