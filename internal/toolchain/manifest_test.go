package toolchain

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestManifestCompleteForPrimaryPlatforms(t *testing.T) {
	want := []string{"opengrep", "gosec", "osv-scanner", "trivy", "gitleaks"}
	for _, name := range want {
		tool, err := Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, plat := range []string{"linux/amd64", "darwin/arm64"} {
			a, ok := tool.Assets[plat]
			if !ok {
				t.Errorf("%s: no asset for %s", name, plat)
				continue
			}
			if err := checkSHA256Hex(a.SHA256); err != nil {
				t.Errorf("%s %s: %v", name, plat, err)
			}
		}
	}
	if len(Tools()) != len(want) {
		t.Errorf("manifest has %d tools, want %d", len(Tools()), len(want))
	}
}

func TestManifestAssetsWellFormed(t *testing.T) {
	seenURL := map[string]string{}
	for _, tool := range Tools() {
		if tool.Version == "" || strings.HasPrefix(tool.Version, "v") {
			t.Errorf("%s: version %q must be set without a leading v", tool.Name, tool.Version)
		}
		if len(tool.VersionArgs) == 0 {
			t.Errorf("%s: no version probe", tool.Name)
		}
		for plat, a := range tool.Assets {
			id := tool.Name + " " + plat
			if !strings.HasPrefix(a.URL, "https://github.com/") {
				t.Errorf("%s: url %q must be an https github.com release URL", id, a.URL)
			}
			if !strings.Contains(a.URL, tool.Version) {
				t.Errorf("%s: url %q does not mention pinned version %s", id, a.URL, tool.Version)
			}
			if prev, dup := seenURL[a.URL]; dup {
				t.Errorf("%s duplicates the URL of %s", id, prev)
			}
			seenURL[a.URL] = id
			if err := checkSHA256Hex(a.SHA256); err != nil || a.SHA256 != strings.ToLower(a.SHA256) {
				t.Errorf("%s: bad sha256 %q", id, a.SHA256)
			}
			switch a.Archive {
			case Raw:
				if a.Member != "" {
					t.Errorf("%s: raw asset must not name a member", id)
				}
			case TarGz, Zip:
				want := tool.Bin
				if strings.HasPrefix(plat, "windows/") {
					want += ".exe"
				}
				if a.Member != want {
					t.Errorf("%s: member %q, want %q", id, a.Member, want)
				}
			default:
				t.Errorf("%s: unknown archive %q", id, a.Archive)
			}
			if strings.HasPrefix(plat, "windows/") && !strings.HasSuffix(a.URL, ".exe") && a.Archive == Raw {
				t.Errorf("%s: raw windows asset should be an .exe", id)
			}
		}
	}
}

func mustRead(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func firstGroup(t *testing.T, re, text, what string) string {
	t.Helper()
	m := regexp.MustCompile(re).FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("could not find %s (regexp %s)", what, re)
	}
	return m[1]
}

// TestManifestMatchesRepoPins fails when the manifest drifts from the versions
// (and, for linux, the digests) pinned in configs/tools.yaml and
// deployments/achilles/Dockerfile, and fails if action.yml re-introduces its own
// scanner pins. Bump them together.
func TestManifestMatchesRepoPins(t *testing.T) {
	var cfg struct {
		Tools []struct {
			ID      string `yaml:"id"`
			Enabled bool   `yaml:"enabled"`
			Image   string `yaml:"image"`
		} `yaml:"tools"`
	}
	if err := yaml.Unmarshal([]byte(mustRead(t, "../../configs/tools.yaml")), &cfg); err != nil {
		t.Fatal(err)
	}
	imgTag := regexp.MustCompile(`:v?(\d+\.\d+\.\d+)@sha256:`)
	enabled := map[string]bool{}
	images := map[string]string{}
	for _, tc := range cfg.Tools {
		if tc.Enabled {
			enabled[tc.ID] = true
		}
		if m := imgTag.FindStringSubmatch(tc.Image); m != nil {
			images[tc.ID] = m[1]
		}
	}

	action := mustRead(t, "../../action.yml")
	docker := mustRead(t, "../../deployments/achilles/Dockerfile")

	// Version pins per source. The manifest is the single source of truth for the
	// scanner pins: action.yml no longer pins any (it runs `achilles tools install`).
	dockerV := map[string]string{
		"opengrep":    strings.TrimPrefix(firstGroup(t, `ARG OPENGREP_VERSION=v?([\d.]+)`, docker, "Dockerfile OPENGREP_VERSION"), "v"),
		"gosec":       firstGroup(t, `ARG GOSEC_VERSION=v?([\d.]+)`, docker, "Dockerfile GOSEC_VERSION"),
		"osv-scanner": firstGroup(t, `ARG OSV_SCANNER_VERSION=v?([\d.]+)`, docker, "Dockerfile OSV_SCANNER_VERSION"),
		"trivy":       firstGroup(t, `ARG TRIVY_VERSION=([\d.]+)`, docker, "Dockerfile TRIVY_VERSION"),
		"gitleaks":    firstGroup(t, `ARG GITLEAKS_VERSION=([\d.]+)`, docker, "Dockerfile GITLEAKS_VERSION"),
	}

	for _, tool := range Tools() {
		if v, ok := images[tool.Name]; ok && v != tool.Version {
			t.Errorf("%s: manifest %s != configs/tools.yaml image tag %s", tool.Name, tool.Version, v)
		}
		if strings.Contains(action, tool.Version) {
			t.Errorf("%s: action.yml hard-codes the scanner version %s; the manifest is the only pin", tool.Name, tool.Version)
		}
		if v := dockerV[tool.Name]; v != tool.Version {
			t.Errorf("%s: manifest %s != Dockerfile %s", tool.Name, tool.Version, v)
		}
		// Opengrep has no image in tools.yaml; every other tool must have one.
		if _, ok := images[tool.Name]; !ok && tool.Name != "opengrep" {
			t.Errorf("%s: no pinned image tag found in configs/tools.yaml", tool.Name)
		}
		if tool.Default != enabled[tool.Name] {
			t.Errorf("%s: manifest Default=%v but configs/tools.yaml enabled=%v", tool.Name, tool.Default, enabled[tool.Name])
		}
	}
	for id := range enabled {
		if _, err := Lookup(id); err != nil {
			t.Errorf("configs/tools.yaml enables %q but the toolchain manifest does not know it", id)
		}
	}

	if strings.Contains(action, "go install") {
		t.Error("action.yml must not `go install` scanners; use `achilles tools install`")
	}

	// Linux digests must agree with the ones pinned in the Dockerfile.
	for _, name := range []string{"trivy", "gitleaks"} {
		tool, _ := Lookup(name)
		for _, plat := range []string{"linux/amd64", "linux/arm64"} {
			sha := tool.Assets[plat].SHA256
			if !strings.Contains(docker, sha) {
				t.Errorf("%s %s: digest %s not found in Dockerfile", name, plat, sha)
			}
		}
	}
	og, _ := Lookup("opengrep")
	for _, plat := range []string{"linux/amd64", "linux/arm64"} {
		if sha := og.Assets[plat].SHA256; !strings.Contains(docker, sha) {
			t.Errorf("opengrep %s: digest %s not found in Dockerfile", plat, sha)
		}
	}
}
