//go:build !unix

package vault

import "os"

// No advisory locking on this platform: the file backend is single-process here.
func lockFile(*os.File) error { return nil }
func unlockFile(*os.File)     {}
