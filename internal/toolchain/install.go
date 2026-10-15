package toolchain

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// defaultMaxDownload bounds a single download; the largest pinned asset
	// (Trivy for Windows) is ~52 MB compressed.
	defaultMaxDownload int64 = 512 << 20
	// defaultMaxBinary bounds the extracted executable (Trivy is ~170 MB).
	defaultMaxBinary int64 = 512 << 20
)

// Installer downloads a pinned asset, verifies its sha256 (failing closed), and
// writes exactly one executable into BinDir.
type Installer struct {
	BinDir string
	Client *http.Client // nil = a client that only follows https redirects
	Log    io.Writer    // progress lines; nil = silent

	MaxDownload int64 // 0 = defaultMaxDownload
	MaxBinary   int64 // 0 = defaultMaxBinary

	// Go is the go executable to build tools that name a GoPackage with ("" =
	// always download the prebuilt binary). See buildFromSource.
	Go string

	allowHTTP bool // tests only: the httptest server is plain http
	// goRunner replaces running Go (tests only).
	goRunner func(ctx context.Context, dir string, env []string, args ...string) ([]byte, error)
}

func (in *Installer) logf(format string, a ...any) {
	if in.Log != nil {
		fmt.Fprintf(in.Log, format+"\n", a...)
	}
}

func (in *Installer) client() *http.Client {
	if in.Client != nil {
		return in.Client
	}
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if req.URL.Scheme != "https" && !in.allowHTTP {
				return fmt.Errorf("refusing redirect to non-https URL %s", req.URL.Redacted())
			}
			return nil
		},
	}
}

// Install installs tool t for the given platform and returns the installed path.
// It is a no-op error (ErrNoAsset) when upstream publishes nothing for the platform.
//
// A tool with a GoPackage is built from source when Go is available and the
// platform is this machine's, and downloaded only if that fails.
func (in *Installer) Install(ctx context.Context, t Tool, goos, goarch string) (string, error) {
	if t.GoPackage != "" && in.Go != "" && goos == runtime.GOOS && goarch == runtime.GOARCH {
		p, err := in.buildFromSource(ctx, t, goos)
		if err == nil {
			return p, nil
		}
		if ctx.Err() != nil {
			return "", fmt.Errorf("%s: %w", t.Name, ctx.Err())
		}
		in.logf("%s: could not build it from source (%v); downloading the prebuilt binary instead, which may not read code that needs a newer Go than it was built with", t.Name, err)
	}
	a, ok := t.Asset(goos, goarch)
	if !ok {
		return "", &NoAssetError{Tool: t, GOOS: goos, GOARCH: goarch}
	}
	in.logf("%s %s: downloading %s", t.Name, t.Version, a.URL)
	p, err := in.installAsset(ctx, exeName(goos, t.Bin), a)
	if err != nil {
		return "", fmt.Errorf("%s: %w", t.Name, err)
	}
	return p, nil
}

// NoAssetError means the manifest has no asset for the platform.
type NoAssetError struct {
	Tool         Tool
	GOOS, GOARCH string
}

func (e *NoAssetError) Error() string {
	return fmt.Sprintf("no pinned %s asset for %s/%s: install it manually (%s)", e.Tool.Name, e.GOOS, e.GOARCH, e.Tool.Manual)
}

// installAsset is Install without the manifest lookup (tests drive it directly).
func (in *Installer) installAsset(ctx context.Context, finalName string, a Asset) (string, error) {
	if in.BinDir == "" {
		return "", errors.New("no install directory")
	}
	if err := checkSHA256Hex(a.SHA256); err != nil {
		return "", fmt.Errorf("manifest digest: %w", err)
	}
	if err := in.requireHTTPS(a.URL); err != nil {
		return "", err
	}
	if err := ensureDir(in.BinDir); err != nil {
		return "", err
	}

	dl, err := in.downloadVerified(ctx, a)
	if err != nil {
		return "", err
	}
	dlPath := dl.Name()
	keepDownload := false // true once the download itself becomes the final file
	defer func() {
		dl.Close()
		if !keepDownload {
			os.Remove(dlPath)
		}
	}()

	final := filepath.Join(in.BinDir, finalName)
	if a.Archive == Raw {
		if err := dl.Close(); err != nil {
			return "", err
		}
		if err := os.Chmod(dlPath, 0o755); err != nil {
			return "", err
		}
		if err := os.Rename(dlPath, final); err != nil {
			return "", fmt.Errorf("install %s: %w", final, err)
		}
		keepDownload = true
		return final, nil
	}

	out, err := os.CreateTemp(in.BinDir, ".bin-*")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	outPath := out.Name()
	defer func() {
		out.Close()
		os.Remove(outPath) // no-op after a successful rename
	}()

	max := in.MaxBinary
	if max <= 0 {
		max = defaultMaxBinary
	}
	switch a.Archive {
	case TarGz:
		err = extractTarGz(dl, a.Member, out, max)
	case Zip:
		err = extractZip(dl, a.Member, out, max)
	default:
		err = fmt.Errorf("unsupported archive type %q", a.Archive)
	}
	if err != nil {
		return "", err
	}
	if err := out.Sync(); err != nil {
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(outPath, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(outPath, final); err != nil {
		return "", fmt.Errorf("install %s: %w", final, err)
	}
	return final, nil
}

// downloadVerified downloads a into a temp file in BinDir and checks its sha256.
// FAIL CLOSED: on any error (including a digest mismatch) the temp file is
// removed and nothing is returned; the caller removes the file when finished.
func (in *Installer) downloadVerified(ctx context.Context, a Asset) (*os.File, error) {
	dl, err := os.CreateTemp(in.BinDir, ".dl-*")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	got, err := in.download(ctx, a.URL, dl)
	if err == nil && got != strings.ToLower(a.SHA256) {
		err = fmt.Errorf("sha256 mismatch for %s: got %s, want %s (refusing to install)", a.URL, got, a.SHA256)
	}
	if err != nil {
		dl.Close()
		os.Remove(dl.Name())
		return nil, err
	}
	return dl, nil
}

func (in *Installer) requireHTTPS(raw string) error {
	if strings.HasPrefix(raw, "https://") || (in.allowHTTP && strings.HasPrefix(raw, "http://")) {
		return nil
	}
	return fmt.Errorf("refusing non-https download URL %q", raw)
}

// download streams url into f (bounded) and returns the lowercase hex sha256.
func (in *Installer) download(ctx context.Context, url string, f *os.File) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "achilles-tools")
	resp, err := in.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	max := in.MaxDownload
	if max <= 0 {
		max = defaultMaxDownload
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, max+1))
	if err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	if n > max {
		return "", fmt.Errorf("download %s exceeds the %d byte limit", url, max)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func checkSHA256Hex(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("sha256 %q is not 64 hex characters", s)
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("sha256 %q is not hex", s)
	}
	return nil
}

func ensureDir(bin string) error {
	// The parent (~/.achilles) holds other state; keep it owner-only. The bin dir
	// itself is conventional 0755 (the binaries must be executable).
	if parent := filepath.Dir(bin); parent != bin {
		if _, err := os.Stat(parent); os.IsNotExist(err) {
			if err := os.MkdirAll(parent, 0o700); err != nil {
				return fmt.Errorf("create %s: %w", parent, err)
			}
		}
	}
	if err := os.MkdirAll(bin, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", bin, err)
	}
	return nil
}

// unsafeEntryName reports archive member names that could escape a directory if
// anyone ever extracted by name: absolute paths, drive letters, backslashes, or
// any ".." segment. We never write by member name, but a hostile archive is
// rejected outright rather than half-trusted.
func unsafeEntryName(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\\x00") {
		return true
	}
	if len(name) >= 2 && name[1] == ':' {
		return true
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

func sameMember(name, member string) bool {
	return path.Clean(strings.TrimPrefix(name, "./")) == member
}

// copyCapped copies at most max bytes and errors if src has more.
func copyCapped(dst io.Writer, src io.Reader, max int64) error {
	n, err := io.Copy(dst, io.LimitReader(src, max+1))
	if err != nil {
		return err
	}
	if n > max {
		return fmt.Errorf("extracted file exceeds the %d byte limit", max)
	}
	return nil
}

func extractTarGz(src io.ReadSeeker, member string, dst io.Writer, max int64) error {
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	gz, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		if unsafeEntryName(hdr.Name) {
			return fmt.Errorf("archive entry %q has an unsafe path", hdr.Name)
		}
		if !sameMember(hdr.Name, member) {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("archive entry %q is not a regular file", hdr.Name)
		}
		if hdr.Size > max {
			return fmt.Errorf("archive entry %q is %d bytes, over the %d byte limit", hdr.Name, hdr.Size, max)
		}
		if found {
			return fmt.Errorf("archive has more than one %q", member)
		}
		if err := copyCapped(dst, tr, max); err != nil {
			return err
		}
		found = true
	}
	if !found {
		return fmt.Errorf("archive does not contain %q", member)
	}
	return nil
}

func extractZip(src *os.File, member string, dst io.Writer, max int64) error {
	st, err := src.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(src, st.Size())
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	var target *zip.File
	for _, f := range zr.File {
		if unsafeEntryName(f.Name) {
			return fmt.Errorf("archive entry %q has an unsafe path", f.Name)
		}
		if !sameMember(f.Name, member) {
			continue
		}
		if !f.Mode().IsRegular() {
			return fmt.Errorf("archive entry %q is not a regular file", f.Name)
		}
		if max < 0 || f.UncompressedSize64 > uint64(max) {
			return fmt.Errorf("archive entry %q is %d bytes, over the %d byte limit", f.Name, f.UncompressedSize64, max)
		}
		if target != nil {
			return fmt.Errorf("archive has more than one %q", member)
		}
		target = f
	}
	if target == nil {
		return fmt.Errorf("archive does not contain %q", member)
	}
	rc, err := target.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	return copyCapped(dst, rc, max)
}
