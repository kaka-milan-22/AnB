//go:build linux

package keystore

import "golang.org/x/sys/unix"

// Harden applies best-effort, fail-open process memory hygiene on Linux:
//   - RLIMIT_CORE=0     : no core dump can capture the key
//   - PR_SET_DUMPABLE=0 : not ptrace/dumpable by same-uid tools
//   - mlockall          : keep all current+future pages out of swap
//
// None is a substitute for the mTLS/authz boundary; a daemon that runs slightly
// less hardened still beats one that refuses to start.
func Harden() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	_ = unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)
}
