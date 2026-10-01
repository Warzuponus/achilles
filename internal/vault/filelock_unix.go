//go:build unix

package vault

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock, blocking until it is held. flock is
// per open file description, so it excludes other processes and also other
// FileStore instances in the same process.
func lockFile(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			return err
		}
	}
}

func unlockFile(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
