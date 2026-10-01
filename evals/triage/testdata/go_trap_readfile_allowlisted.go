package cases

import (
	"os"
	"strconv"
)

// reportCount is how many numbered report files exist.
const reportCount = 3

// readUserFile returns the numbered report file at the given menu index.
func readUserFile(index int) ([]byte, error) {
	if index < 0 || index >= reportCount {
		return nil, os.ErrNotExist
	}
	userControlledPath := "/var/app/files/report-" + strconv.Itoa(index) + ".csv"
	return os.ReadFile(userControlledPath)
}
