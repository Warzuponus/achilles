package cases

import (
	"net/http"
	"os/exec"
)

// convert renders the file named in the request to a PNG.
func convert(r *http.Request) ([]byte, error) {
	target := r.FormValue("file")
	cmd := exec.Command("sh", "-c", "convert "+target+" /tmp/out.png")
	return cmd.Output()
}
