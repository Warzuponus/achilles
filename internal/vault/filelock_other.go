//go:build !unix && !windows

package vault

import "os"

// No file locking on this platform (neither flock nor LockFileEx): the file
// backend is single-process here.
func lockFile(*os.File) error { return nil }
func unlockFile(*os.File)     {}
