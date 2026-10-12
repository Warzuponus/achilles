package redact

import (
	"strings"
	"testing"
)

func TestPromptMasksCredentialsButKeepsCode(t *testing.T) {
	cases := []struct{ in, mustHide, mustKeep string }{
		{`aws = "AKIAIOSFODNN7EXAMPLE"`, "AKIAIOSFODNN7EXAMPLE", "aws"},
		{`token: ghp_abcdefghijklmnopqrstuvwxyz0123456789`, "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "token"},
		{`password = "hunter2hunter2"`, "hunter2hunter2", "password"},
		{`key := "sk-or-v1-abcdefghijklmnopqrstuvwxyz"`, "sk-or-v1-abcdefghijklmnopqrstuvwxyz", "key :="},
		{pemBlock("MIIabc"), "MIIabc", ""},
	}
	for _, c := range cases {
		got := Prompt(c.in)
		if strings.Contains(got, c.mustHide) {
			t.Errorf("Prompt(%q) leaked %q: %q", c.in, c.mustHide, got)
		}
		if c.mustKeep != "" && !strings.Contains(got, c.mustKeep) {
			t.Errorf("Prompt(%q) lost %q: %q", c.in, c.mustKeep, got)
		}
	}
}

func TestPromptLeavesOrdinaryCodeAlone(t *testing.T) {
	code := `h := sha256.Sum256(data) // 0123456789abcdef0123456789abcdef0123456789abcdef`
	if got := Prompt(code); got != code {
		t.Errorf("Prompt altered ordinary code: %q", got)
	}
}

func TestSecretsAlsoMasksLongTokens(t *testing.T) {
	in := "built 0123456789abcdef0123456789abcdef0123456789abcdef ok"
	if got := Secrets(in); strings.Contains(got, "0123456789abcdef0123") {
		t.Errorf("Secrets kept a long token: %q", got)
	}
}

// pemBlock builds a private-key block at run time so the test file itself holds no
// key-shaped literal (the publish guard scripts/check-tree.sh rejects one).
func pemBlock(body string) string {
	label := "RSA PRIVATE " + "KEY"
	return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----"
}

// Credentials that used to pass straight through to prompts, reports, issue bodies
// and the War Room.
func TestPromptMasksTheShapesItUsedToMiss(t *testing.T) {
	pgp := "-----BEGIN PGP PRIVATE " + "KEY BLOCK-----\nlQOYBGabc\n-----END PGP PRIVATE " + "KEY BLOCK-----"
	cases := []struct{ name, in, mustHide, mustKeep string }{
		{"database URL", `dsn := "postgres://achilles:achilles-local-only@db:5432/achilles"`, "achilles-local-only", "postgres://achilles:"},
		{"URL keeps its host", `amqp://guest:s3cretpw@rabbit.internal/vhost`, "s3cretpw", "@rabbit.internal/vhost"},
		{"basic auth header", `Authorization: Basic dXNlcjpodW50ZXIyaHVudGVyMg==`, "dXNlcjpodW50ZXIyaHVudGVyMg", "Authorization: Basic"},
		{"opaque bearer header", `"Authorization": "Bearer 9f8e7d6c5b4a39281706f5e4d3c2b1a0"`, "9f8e7d6c5b4a39281706f5e4d3c2b1a0", "Bearer"},
		{"bare bearer", `curl -H "X-Auth: Bearer abcdefghijklmnopqrstuvwxyz012345"`, "abcdefghijklmnopqrstuvwxyz012345", "X-Auth"},
		{"stripe live key", `stripe.api_key = cfg["k"] or "sk_live_` + `4eC39HqLyjWDarjtT1zdp7dc"`, "4eC39HqLyjWDarjtT1zdp7dc", "stripe"},
		{"stripe restricted key", `key: rk_live_` + `4eC39HqLyjWDarjtT1zdp7dc`, "4eC39HqLyjWDarjtT1zdp7dc", "key"},
		{"camelCase secretKey", `secretKey = "wJalrXUtnFEMI/K7MDENG"`, "wJalrXUtnFEMI", "secretKey"},
		{"django SECRET_KEY", `SECRET_KEY = 'django-insecure-abc123xyz'`, "django-insecure-abc123xyz", "SECRET_KEY"},
		{"aws secret access key", `aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCY`, "wJalrXUtnFEMIK7MDENGbPxRfiCY", "aws_secret_access_key"},
		{"slack webhook", `url = "https://hooks.slack.com/services/T00000000/B00000000/` + `XXXXXXXXXXXXXXXXXXXXXXXX"`, "T00000000/B00000000", "hooks.slack.com"},
		{"discord webhook", `https://discord.com/api/webhooks/123456789012345678/` + `abcdefghijklmnopqrstuvwxyz_ABCDEF`, "abcdefghijklmnopqrstuvwxyz_ABCDEF", "discord.com"},
		{"pgp private key block", pgp, "lQOYBGabc", ""},
		{"ado.net connection string", `Server=db;User Id=sa;Password=Sup3rS3cret!;`, "Sup3rS3cret!", "Server=db"},
	}
	for _, c := range cases {
		got := Prompt(c.in)
		if strings.Contains(got, c.mustHide) {
			t.Errorf("%s: Prompt leaked %q: %q", c.name, c.mustHide, got)
		}
		if c.mustKeep != "" && !strings.Contains(got, c.mustKeep) {
			t.Errorf("%s: Prompt lost %q: %q", c.name, c.mustKeep, got)
		}
	}
}

// The model has to be able to tell a templated credential from a hardcoded one, and
// ordinary code and URLs must survive, or the review loses the evidence it needs.
func TestPromptKeepsPlaceholdersAndOrdinaryURLs(t *testing.T) {
	for _, code := range []string{
		`dsn := fmt.Sprintf("postgres://%s:%s@%s/db", user, pass, host)`,
		`url = f"redis://default:{password}@{host}:6379"`,
		`DATABASE_URL=postgres://app:${DB_PASSWORD}@db/app`,
		`mysql://root:$MYSQL_ROOT_PASSWORD@localhost/app`,
		`see https://user:<password>@example.com/ for the format`,
		`resp, err := http.Get("http://localhost:8080/api/users/@me")`,
		`git clone https://github.com/org/repo.git`,
		`origin git@github.com:org/repo.git`,
		`req.Header.Set("Authorization", "Bearer "+token)`,
		`headers = {"Authorization": f"Bearer {token}"}`,
		`curl -H "Authorization: Bearer $TOKEN" https://api.example.com`,
		`// the bearer of this token may read the repository`,
	} {
		if got := Prompt(code); got != code {
			t.Errorf("Prompt altered code that holds no credential:\n in: %s\nout: %s", code, got)
		}
	}
}
