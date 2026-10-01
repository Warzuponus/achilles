BINARY := achilles
BINDIR := bin

.PHONY: all build install release test test-integration verify-tier2 license-check lint fmt vet run clean tidy eval-context eval-gate eval-baseline eval-verdict eval-verdict-ollama

all: build

build:
	go build -o $(BINDIR)/$(BINARY) ./cmd/achilles

install:
	go install ./cmd/achilles

# Cross-compile release binaries into bin/.
release:
	GOOS=linux  GOARCH=amd64 go build -trimpath -o $(BINDIR)/$(BINARY)-linux-amd64   ./cmd/achilles
	GOOS=linux  GOARCH=arm64 go build -trimpath -o $(BINDIR)/$(BINARY)-linux-arm64   ./cmd/achilles
	GOOS=darwin GOARCH=arm64 go build -trimpath -o $(BINDIR)/$(BINARY)-darwin-arm64  ./cmd/achilles

test:
	go test ./...

# Triage eval harness (evals/triage/corpus.yaml). Context mode is hermetic — no
# model, no key — so it runs anywhere and gates in CI against the committed
# baseline. Verdict mode needs a live model and real spend.
eval-context:
	go run ./cmd/achilles-eval --mode context --verbose

eval-gate:
	go run ./cmd/achilles-eval --mode context \
		--baseline evals/triage/baseline-context.json --fail-on-regression

# Check the corpus's claims about external tools by RUNNING those tools. Needs no
# model and no key, but does need gosec/bandit on PATH — a case it cannot check is
# reported as skipped, never as a pass, so this is safe to run anywhere.
eval-corpus:
	go run ./cmd/achilles-eval --mode corpus

# Refresh the committed context baseline after an intentional context change.
eval-baseline:
	go run ./cmd/achilles-eval --mode context --out evals/triage/baseline-context.json

# Eval the models we ACTUALLY run. Evaluating some unrelated model tells you
# nothing about production, so both targets below drive a committed routing config
# rather than a single hand-picked model name — triage and judge deliberately use
# different models, and the score belongs to the pair.

# Ollama Cloud open models (configs/models.ollama.yaml). Needs ACHILLES_LLM_API_KEY.
#   make eval-verdict-ollama EVAL_ARGS="--repeat 3"
eval-verdict-ollama:
	go run ./cmd/achilles-eval --mode verdict \
		--llm-base-url https://ollama.com/v1 --llm-model glm-5.2 \
		--model-config configs/models.ollama.yaml $(EVAL_ARGS)

# Escape hatch for any other static-key endpoint:
#   make eval-verdict EVAL_MODEL=<model> EVAL_ARGS="--repeat 3"
eval-verdict:
	go run ./cmd/achilles-eval --mode verdict --llm-model "$(EVAL_MODEL)" $(EVAL_ARGS)

# Also runs real-tool integration tests where the tool is installed (skips otherwise).
test-integration:
	go test -tags integration ./...

# End-to-end verification of Tier-2 scanners (findsecbugs, psalm) — needs docker.
verify-tier2:
	verify/tier2/verify.sh

# Fail if any Go dependency is copyleft (AGPL/GPL/LGPL) — protects the
# commercial-license posture (AGPL tools are process-boundary only, never imported).
# Needs: go install github.com/google/go-licenses@v1.6.0
license-check:
	go-licenses check ./... --disallowed_types=forbidden,restricted

vet:
	go vet ./...

lint: vet

fmt:
	gofmt -w .

# Demonstrate the normalize->report spine without Docker/Opengrep installed.
run: build
	./$(BINDIR)/$(BINARY) --from-sarif internal/normalize/testdata/sample.sarif

# Render docs/*.md into the self-contained docs/site.html (needs: pip install markdown).
docs-html:
	python3 docs/build.py

clean:
	rm -rf $(BINDIR)

tidy:
	go mod tidy

# The project is local-first: no cloud SDK may creep back into the dependency graph.
check-deps:
	@bad=$$(go list -deps ./... | grep -E 'cloud\.google\.com|google\.golang\.org|golang\.org/x/oauth2|google\.golang\.org/grpc' || true); \
	if [ -n "$$bad" ]; then echo "FAIL: cloud SDK packages in the dependency graph:"; echo "$$bad"; exit 1; fi; \
	if grep -E 'cloud\.google\.com|google\.golang\.org|golang\.org/x/oauth2|aws-sdk|azure-sdk' go.mod >/dev/null; then \
	  echo "FAIL: go.mod lists a cloud SDK module"; exit 1; fi; \
	echo "ok: no cloud SDK modules"
.PHONY: check-deps
