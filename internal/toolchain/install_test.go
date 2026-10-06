package toolchain

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type tarEntry struct {
	name string
	body []byte
	typ  byte
	link string
}

func makeTarGz(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: typ, Linkname: e.link}
		if typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func makeZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(body)
	}
	zw.Close()
	return buf.Bytes()
}

// serve returns a plain-http test server answering every path with body, and an
// Installer pointed at an empty temp dir.
func serve(t *testing.T, body []byte) (*Installer, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return &Installer{BinDir: filepath.Join(t.TempDir(), "home", "bin"), allowHTTP: true}, srv.URL + "/asset"
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	return names
}

func TestInstallTarGz(t *testing.T) {
	bin := []byte("#!/bin/sh\necho fake\n")
	arc := makeTarGz(t,
		tarEntry{name: "LICENSE", body: []byte("x")},
		tarEntry{name: "./tool", body: bin},
	)
	in, url := serve(t, arc)
	got, err := in.installAsset(context.Background(), "tool", Asset{URL: url, Archive: TarGz, Member: "tool", SHA256: sum(arc)})
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(in.BinDir, "tool") {
		t.Fatalf("path = %s", got)
	}
	data, _ := os.ReadFile(got)
	if !bytes.Equal(data, bin) {
		t.Fatalf("content mismatch: %q", data)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(got)
		if st.Mode().Perm() != 0o755 {
			t.Fatalf("mode = %v, want 0755", st.Mode().Perm())
		}
	}
	if names := dirEntries(t, in.BinDir); len(names) != 1 {
		t.Fatalf("leftover files in bin dir: %v", names)
	}
}

func TestInstallZip(t *testing.T) {
	arc := makeZip(t, map[string][]byte{"README": []byte("r"), "tool.exe": []byte("MZfake")})
	in, url := serve(t, arc)
	got, err := in.installAsset(context.Background(), "tool.exe", Asset{URL: url, Archive: Zip, Member: "tool.exe", SHA256: sum(arc)})
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(got); string(data) != "MZfake" {
		t.Fatalf("content = %q", data)
	}
}

func TestInstallRaw(t *testing.T) {
	raw := []byte("\x7fELFfake")
	in, url := serve(t, raw)
	got, err := in.installAsset(context.Background(), "rawtool", Asset{URL: url, Archive: Raw, SHA256: sum(raw)})
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(got); !bytes.Equal(data, raw) {
		t.Fatal("content mismatch")
	}
	if names := dirEntries(t, in.BinDir); len(names) != 1 || names[0] != "rawtool" {
		t.Fatalf("bin dir = %v", names)
	}
}

func TestInstallHashMismatchFailsClosed(t *testing.T) {
	for _, kind := range []ArchiveKind{Raw, TarGz} {
		body := []byte("tampered")
		if kind == TarGz {
			body = makeTarGz(t, tarEntry{name: "tool", body: []byte("evil")})
		}
		in, url := serve(t, body)
		wrong := sum([]byte("what the manifest expected"))
		_, err := in.installAsset(context.Background(), "tool", Asset{URL: url, Archive: kind, Member: "tool", SHA256: wrong})
		if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
			t.Fatalf("%s: want sha256 mismatch error, got %v", kind, err)
		}
		if names := dirEntries(t, in.BinDir); len(names) != 0 {
			t.Fatalf("%s: files left behind after a failed install: %v", kind, names)
		}
	}
}

func TestInstallDoesNotReplaceExistingOnFailure(t *testing.T) {
	in, url := serve(t, []byte("new"))
	if err := os.MkdirAll(in.BinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(in.BinDir, "tool")
	os.WriteFile(existing, []byte("old good binary"), 0o755)
	_, err := in.installAsset(context.Background(), "tool", Asset{URL: url, Archive: Raw, SHA256: sum([]byte("different"))})
	if err == nil {
		t.Fatal("want error")
	}
	if data, _ := os.ReadFile(existing); string(data) != "old good binary" {
		t.Fatalf("existing binary was clobbered: %q", data)
	}
}

func TestInstallRejectsUnsafeArchives(t *testing.T) {
	cases := map[string][]byte{
		"tar traversal":      makeTarGz(t, tarEntry{name: "../../evil", body: []byte("x")}, tarEntry{name: "tool", body: []byte("ok")}),
		"tar absolute":       makeTarGz(t, tarEntry{name: "/etc/passwd", body: []byte("x")}, tarEntry{name: "tool", body: []byte("ok")}),
		"tar symlink member": makeTarGz(t, tarEntry{name: "tool", typ: tar.TypeSymlink, link: "/etc/passwd"}),
		"tar missing member": makeTarGz(t, tarEntry{name: "other", body: []byte("x")}),
		"tar duplicate":      makeTarGz(t, tarEntry{name: "tool", body: []byte("a")}, tarEntry{name: "tool", body: []byte("b")}),
	}
	for name, arc := range cases {
		in, url := serve(t, arc)
		_, err := in.installAsset(context.Background(), "tool", Asset{URL: url, Archive: TarGz, Member: "tool", SHA256: sum(arc)})
		if err == nil {
			t.Errorf("%s: want error", name)
		}
		if names := dirEntries(t, in.BinDir); len(names) != 0 {
			t.Errorf("%s: left files behind: %v", name, names)
		}
	}

	zarc := makeZip(t, map[string][]byte{"..\\..\\evil.exe": []byte("x"), "tool.exe": []byte("ok")})
	in, url := serve(t, zarc)
	if _, err := in.installAsset(context.Background(), "tool.exe", Asset{URL: url, Archive: Zip, Member: "tool.exe", SHA256: sum(zarc)}); err == nil {
		t.Error("zip-slip: want error")
	}
	zarc = makeZip(t, map[string][]byte{"../evil": []byte("x"), "tool.exe": []byte("ok")})
	in, url = serve(t, zarc)
	if _, err := in.installAsset(context.Background(), "tool.exe", Asset{URL: url, Archive: Zip, Member: "tool.exe", SHA256: sum(zarc)}); err == nil {
		t.Error("zip traversal: want error")
	}
}

func TestInstallRejectsOversize(t *testing.T) {
	big := bytes.Repeat([]byte("A"), 4096)

	// member larger than MaxBinary
	arc := makeTarGz(t, tarEntry{name: "tool", body: big})
	in, url := serve(t, arc)
	in.MaxBinary = 1024
	if _, err := in.installAsset(context.Background(), "tool", Asset{URL: url, Archive: TarGz, Member: "tool", SHA256: sum(arc)}); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("tar oversize member: got %v", err)
	}
	if names := dirEntries(t, in.BinDir); len(names) != 0 {
		t.Fatalf("left files behind: %v", names)
	}

	zarc := makeZip(t, map[string][]byte{"tool.exe": big})
	in, url = serve(t, zarc)
	in.MaxBinary = 1024
	if _, err := in.installAsset(context.Background(), "tool.exe", Asset{URL: url, Archive: Zip, Member: "tool.exe", SHA256: sum(zarc)}); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("zip oversize member: got %v", err)
	}

	// download larger than MaxDownload
	in, url = serve(t, big)
	in.MaxDownload = 1024
	if _, err := in.installAsset(context.Background(), "tool", Asset{URL: url, Archive: Raw, SHA256: sum(big)}); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversize download: got %v", err)
	}
	if names := dirEntries(t, in.BinDir); len(names) != 0 {
		t.Fatalf("left files behind: %v", names)
	}
}

func TestInstallRefusesNonHTTPSAndBadStatus(t *testing.T) {
	in := &Installer{BinDir: t.TempDir()}
	_, err := in.installAsset(context.Background(), "t", Asset{URL: "http://example.com/x", Archive: Raw, SHA256: sum(nil)})
	if err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Fatalf("want non-https refusal, got %v", err)
	}

	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	in = &Installer{BinDir: t.TempDir(), allowHTTP: true}
	if _, err := in.installAsset(context.Background(), "t", Asset{URL: srv.URL, Archive: Raw, SHA256: sum(nil)}); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("want HTTP 404 error, got %v", err)
	}
	if names := dirEntries(t, in.BinDir); len(names) != 0 {
		t.Fatalf("left files behind: %v", names)
	}
}

func TestInstallRefusesRedirectToHTTP(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) }))
	defer plain.Close()
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer tls.Close()
	in := &Installer{BinDir: t.TempDir(), Client: nil}
	// Trust the test server's certificate but keep the production redirect policy.
	c := tls.Client()
	c.CheckRedirect = (&Installer{}).client().CheckRedirect
	in.Client = c
	if _, err := in.installAsset(context.Background(), "t", Asset{URL: tls.URL, Archive: Raw, SHA256: sum([]byte("x"))}); err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Fatalf("want redirect refusal, got %v", err)
	}
}

func TestInstallNoAsset(t *testing.T) {
	tool := Tool{Name: "x", Bin: "x", Manual: "do it by hand", Assets: map[string]Asset{}}
	_, err := (&Installer{BinDir: t.TempDir()}).Install(context.Background(), tool, "plan9", "mips")
	var na *NoAssetError
	if !errors.As(err, &na) || !strings.Contains(err.Error(), "do it by hand") {
		t.Fatalf("got %v", err)
	}
}
