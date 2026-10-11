//go:build windows

package vault

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

// lockfileExclusiveLock is LOCKFILE_EXCLUSIVE_LOCK. LOCKFILE_FAIL_IMMEDIATELY is
// deliberately not set, so the call waits for the lock like flock does on unix.
const lockfileExclusiveLock = 0x00000002

// lockFile takes an exclusive lock on f, blocking until it is held. The lock
// belongs to the handle, so it excludes other processes and also other FileStore
// instances in this process. It is taken on the vault's separate .lock file (see
// FileStore.lock), never on the data file: Windows byte-range locks are mandatory
// and would block readers of whatever file they are placed on.
//
// Without this, two processes appending to one vault on Windows computed the same
// sequence number and wrote records with the same ID.
func lockFile(f *os.File) error {
	var ol syscall.Overlapped
	// #nosec G103 -- the Win32 API takes a pointer to an OVERLAPPED struct; it is a local, used only for this call
	r, _, err := procLockFileEx.Call(f.Fd(), lockfileExclusiveLock, 0, 0xFFFFFFFF, 0xFFFFFFFF, uintptr(unsafe.Pointer(&ol)))
	if r == 0 {
		return err
	}
	return nil
}

func unlockFile(f *os.File) {
	var ol syscall.Overlapped
	// #nosec G103 -- as in lockFile
	_, _, _ = procUnlockFileEx.Call(f.Fd(), 0, 0xFFFFFFFF, 0xFFFFFFFF, uintptr(unsafe.Pointer(&ol)))
}
