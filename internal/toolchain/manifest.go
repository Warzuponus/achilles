package toolchain

import (
	"fmt"
	"sort"
)

// ArchiveKind says how an asset is packaged.
type ArchiveKind string

const (
	Raw   ArchiveKind = "raw"    // the download IS the executable
	TarGz ArchiveKind = "tar.gz" // extract Member
	Zip   ArchiveKind = "zip"    // extract Member
)

// Asset is one downloadable upstream release artifact for one platform.
type Asset struct {
	URL     string      // https URL of the release asset
	Archive ArchiveKind // packaging
	Member  string      // path of the executable inside the archive (ignored for Raw)
	SHA256  string      // lowercase hex digest of the DOWNLOAD (the archive, or the raw binary)
}

// Tool is one pinned scanner.
type Tool struct {
	Name    string // id in configs/tools.yaml
	Bin     string // executable name without .exe
	Version string // pinned version, no leading "v"
	// Default marks tools the default scan profile needs; `achilles doctor` fails
	// when one of these is missing.
	Default bool
	// VersionArgs is the argv that makes the tool print its version.
	VersionArgs []string
	// Requires are executables the tool shells out to (checked by doctor).
	Requires []string
	// Assets by "goos/goarch". A platform that is absent here has NO upstream
	// asset (or none we pin): doctor says "install manually / use Docker".
	Assets map[string]Asset
	// Manual is the hint printed for platforms without an asset.
	Manual string
}

// Asset returns the asset for a platform.
func (t Tool) Asset(goos, goarch string) (Asset, bool) {
	a, ok := t.Assets[platformKey(goos, goarch)]
	return a, ok
}

// gh builds a GitHub release download URL.
func gh(repo, tag, file string) string {
	return "https://github.com/" + repo + "/releases/download/" + tag + "/" + file
}

// Versions here are the single source of truth for the pinned scanners. They must
// agree with configs/tools.yaml image tags and deployments/achilles/Dockerfile
// (action.yml pins nothing: it runs `achilles tools install`) — TestManifestMatchesRepoPins enforces that, so
// bump all of them together.
//
// Hash provenance (re-verify when bumping: fetch the file named below and copy the
// digest for each asset):
//
//	gosec        gosec_2.27.1_checksums.txt     (published by upstream)
//	osv-scanner  osv-scanner_SHA256SUMS         (published by upstream)
//	trivy        trivy_0.72.0_checksums.txt     (published by upstream)
//	gitleaks     gitleaks_8.30.1_checksums.txt  (published by upstream)
//	opengrep     NO upstream checksums: sha256sum of each downloaded release asset
//	             (trust on first use, 2026-10-05). The linux digests agree with the
//	             ones pinned independently in deployments/achilles/Dockerfile.
//
// The linux trivy/gitleaks/opengrep digests also agree with the Dockerfile
// (asserted by TestManifestMatchesRepoPins).
//
// Platforms: linux amd64/arm64, darwin amd64/arm64, windows amd64. Upstream
// publishes no windows/arm64 asset for opengrep or trivy, so windows/arm64 is
// omitted for every tool. Opengrep's linux assets are the glibc "manylinux"
// builds; musl (Alpine) users should use the Docker image.
var manifest = []Tool{
	{
		Name: "opengrep", Bin: "opengrep", Version: "1.25.0", Default: true,
		VersionArgs: []string{"--version"},
		Manual:      "download a release from https://github.com/opengrep/opengrep/releases, or use the Achilles Docker image",
		Assets: map[string]Asset{
			"linux/amd64":   {gh("opengrep/opengrep", "v1.25.0", "opengrep_manylinux_x86"), Raw, "", "9ac4aebb47ba3f7b0d8fc641ac8749cb6c2f253f616131a67d9631e00d4bea33"},
			"linux/arm64":   {gh("opengrep/opengrep", "v1.25.0", "opengrep_manylinux_aarch64"), Raw, "", "fd40124272d006082a5594b19aecee07b01dd50933d8add7a4fd5c557d2be5f6"},
			"darwin/amd64":  {gh("opengrep/opengrep", "v1.25.0", "opengrep_osx_x86"), Raw, "", "fa2487b75527be1cc9ae4f9b0cb09a340454e7973c76785568285cbbcd977cb4"},
			"darwin/arm64":  {gh("opengrep/opengrep", "v1.25.0", "opengrep_osx_arm64"), Raw, "", "3543fcabae9db2ae5bc974a3b75426353f0a3e369181b2157ef27f46867996c8"},
			"windows/amd64": {gh("opengrep/opengrep", "v1.25.0", "opengrep_windows_x86.exe"), Raw, "", "b010709bb790086083442eabe9a0b6bf48064ed87cdf808591baecdb60ccdf73"},
		},
	},
	{
		Name: "gosec", Bin: "gosec", Version: "2.27.1", Default: true,
		VersionArgs: []string{"-version"},
		Requires:    []string{"go"}, // gosec type-checks via the Go toolchain
		Manual:      "go install github.com/securego/gosec/v2/cmd/gosec@v2.27.1, or use the Achilles Docker image",
		Assets: map[string]Asset{
			"linux/amd64":   {gh("securego/gosec", "v2.27.1", "gosec_2.27.1_linux_amd64.tar.gz"), TarGz, "gosec", "a1cc5fba45fb51131ba05dee4029b364f62f4b6739b8f24236f93de82f40da40"},
			"linux/arm64":   {gh("securego/gosec", "v2.27.1", "gosec_2.27.1_linux_arm64.tar.gz"), TarGz, "gosec", "33582a6ed6878e4a0456585a8c3b043eef74d989d606bef85afc1a0f9b12f475"},
			"darwin/amd64":  {gh("securego/gosec", "v2.27.1", "gosec_2.27.1_darwin_amd64.tar.gz"), TarGz, "gosec", "117cf8dfe02b8746dad579f6ad01019e7c548bb36451e400993d662714dddcd9"},
			"darwin/arm64":  {gh("securego/gosec", "v2.27.1", "gosec_2.27.1_darwin_arm64.tar.gz"), TarGz, "gosec", "e2d31bb4572471f47489dd6d2f3c98e9261dc65b1889c2a01c48d73d4e40038b"},
			"windows/amd64": {gh("securego/gosec", "v2.27.1", "gosec_2.27.1_windows_amd64.tar.gz"), TarGz, "gosec.exe", "5f775953d10f1bbb407e33b388c5922a10c6b5dae24033bd2a930743d932308c"},
		},
	},
	{
		Name: "osv-scanner", Bin: "osv-scanner", Version: "2.4.0", Default: true,
		VersionArgs: []string{"--version"},
		Manual:      "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.4.0, or use the Achilles Docker image",
		Assets: map[string]Asset{
			"linux/amd64":   {gh("google/osv-scanner", "v2.4.0", "osv-scanner_linux_amd64"), Raw, "", "15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0"},
			"linux/arm64":   {gh("google/osv-scanner", "v2.4.0", "osv-scanner_linux_arm64"), Raw, "", "44e580752910f0ff36ec99aff59af20f65df1e859aa31e5605a8f0d055b496e9"},
			"darwin/amd64":  {gh("google/osv-scanner", "v2.4.0", "osv-scanner_darwin_amd64"), Raw, "", "088119325156321c34c456ac3703d6013538fd71cbac82b891ab34db491e4d66"},
			"darwin/arm64":  {gh("google/osv-scanner", "v2.4.0", "osv-scanner_darwin_arm64"), Raw, "", "9ca3185ad63e9ab54f7cb90f46a7362be02d80e37f0123d095a54355ea202f5d"},
			"windows/amd64": {gh("google/osv-scanner", "v2.4.0", "osv-scanner_windows_amd64.exe"), Raw, "", "0cdd113610126d5dfd5e12ad0e0b4f3e879291ff19bb43b0c52ed2f2c2df1a37"},
		},
	},
	{
		Name: "trivy", Bin: "trivy", Version: "0.72.0", Default: true,
		VersionArgs: []string{"--version"},
		Manual:      "see https://trivy.dev/latest/getting-started/installation/, or use the Achilles Docker image",
		Assets: map[string]Asset{
			"linux/amd64":   {gh("aquasecurity/trivy", "v0.72.0", "trivy_0.72.0_Linux-64bit.tar.gz"), TarGz, "trivy", "bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea"},
			"linux/arm64":   {gh("aquasecurity/trivy", "v0.72.0", "trivy_0.72.0_Linux-ARM64.tar.gz"), TarGz, "trivy", "2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467"},
			"darwin/amd64":  {gh("aquasecurity/trivy", "v0.72.0", "trivy_0.72.0_macOS-64bit.tar.gz"), TarGz, "trivy", "ee5e60df8a98e5b89fd74a6d86f9e5c7e9a266a35002cb1e43291698b3bfee08"},
			"darwin/arm64":  {gh("aquasecurity/trivy", "v0.72.0", "trivy_0.72.0_macOS-ARM64.tar.gz"), TarGz, "trivy", "88f208680dc05da2b459e19b4f5aa2b4dc7c2117892ba4aab2ae63baba330016"},
			"windows/amd64": {gh("aquasecurity/trivy", "v0.72.0", "trivy_0.72.0_windows-64bit.zip"), Zip, "trivy.exe", "ed3cf122060f61818fe1f735fd97557954e16e10bc8b058af9852271cf2e91b3"},
		},
	},
	{
		Name: "gitleaks", Bin: "gitleaks", Version: "8.30.1", Default: true,
		VersionArgs: []string{"version"},
		Manual:      "download a release from https://github.com/gitleaks/gitleaks/releases, or use the Achilles Docker image",
		Assets: map[string]Asset{
			"linux/amd64":   {gh("gitleaks/gitleaks", "v8.30.1", "gitleaks_8.30.1_linux_x64.tar.gz"), TarGz, "gitleaks", "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"},
			"linux/arm64":   {gh("gitleaks/gitleaks", "v8.30.1", "gitleaks_8.30.1_linux_arm64.tar.gz"), TarGz, "gitleaks", "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"},
			"darwin/amd64":  {gh("gitleaks/gitleaks", "v8.30.1", "gitleaks_8.30.1_darwin_x64.tar.gz"), TarGz, "gitleaks", "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709"},
			"darwin/arm64":  {gh("gitleaks/gitleaks", "v8.30.1", "gitleaks_8.30.1_darwin_arm64.tar.gz"), TarGz, "gitleaks", "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"},
			"windows/amd64": {gh("gitleaks/gitleaks", "v8.30.1", "gitleaks_8.30.1_windows_x64.zip"), Zip, "gitleaks.exe", "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e"},
		},
	},
}

// Tools returns the pinned tools in a stable (alphabetical) order.
func Tools() []Tool {
	out := append([]Tool(nil), manifest...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup finds a pinned tool by name.
func Lookup(name string) (Tool, error) {
	names := make([]string, 0, len(manifest))
	for _, t := range manifest {
		if t.Name == name {
			return t, nil
		}
		names = append(names, t.Name)
	}
	sort.Strings(names)
	return Tool{}, fmt.Errorf("unknown tool %q (known: %v)", name, names)
}
