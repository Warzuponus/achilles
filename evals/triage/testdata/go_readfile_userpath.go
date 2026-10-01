package cases

import (
	"net/http"
	"os"
)

// download serves a file from the shared files directory.
func download(r *http.Request) ([]byte, error) {
	name := r.URL.Query().Get("name")
	return os.ReadFile("/var/app/files/" + name)
}
