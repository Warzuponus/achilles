// A deliberately vulnerable sample for the Achilles quickstart. Do not deploy.
package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

func main() {
	http.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		// Command injection: request data reaches exec.
		out, _ := exec.Command("sh", "-c", r.URL.Query().Get("cmd")).Output()
		w.Write(out)
	})
	http.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		// Path traversal: request data chooses the file.
		b, _ := os.ReadFile(r.URL.Query().Get("p"))
		w.Write(b)
	})
	fmt.Println(http.ListenAndServe(":8081", nil))
}
