//go:build darwin

package keystore

import "golang.org/x/sys/unix"

// Harden applies the cross-platform subset of memory hygiene on macOS: disable
// core dumps and lock pages out of swap. PR_SET_DUMPABLE has no portable
// equivalent here, and PT_DENY_ATTACH is deliberately omitted (it breaks
// debuggers/crash reporters for marginal gain given the mTLS boundary).
func Harden() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	_ = unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)
}
