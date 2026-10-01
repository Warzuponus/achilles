package cases

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const filesRoot = "/var/app/files"

// readReport returns the report named in the request. filepath.Join cleans the
// result, so the prefix check below rejects any name that traverses out of
// filesRoot before it reaches the filesystem.
func readReport(r *http.Request) ([]byte, error) {
	full := filepath.Join(filesRoot, r.URL.Query().Get("name"))
	if !strings.HasPrefix(full, filesRoot+string(os.PathSeparator)) {
		return nil, fmt.Errorf("path escapes %s", filesRoot)
	}
	return os.ReadFile(full)
}
