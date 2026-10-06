// Deliberately vulnerable demo service. Benchmark fixture: never run, never ship.
// This directory is its own Go module so `go build ./...` in the parent repo
// ignores it.
package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

var db *sql.DB

const adminPassword = "hunter2-admin-pass"

func userHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query(fmt.Sprintf("SELECT id FROM users WHERE name = '%s'", name))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	w.Write(out)
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	data, err := os.ReadFile(filepath.Join("/srv/uploads", name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write(data)
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(r.URL.Query().Get("url"))
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func hashPassword(p string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(p)))
}

func main() {
	http.HandleFunc("/user", userHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/file", fileHandler)
	http.HandleFunc("/proxy", proxyHandler)
	http.ListenAndServe(":8080", nil)
}
