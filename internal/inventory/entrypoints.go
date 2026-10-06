package inventory

import (
	"bytes"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Entry-point kinds. They name how attacker-influenced data can enter a file, not
// how dangerous that is.
const (
	KindHTTPRoute = "http-route" // an HTTP route or request handler
	KindRequest   = "request-input"
	KindGRPC      = "grpc"
	KindCLI       = "cli-args"
	KindConsumer  = "consumer" // a queue, event, stdin or file consumer
)

// EntryPoint is one place a file exposes itself to input an attacker may
// influence. It is a HINT from a line-level pattern match, never a proof: no
// parsing, no cross-file resolution, and a file with no hints is not thereby
// unreachable (a handler can be registered from another file).
type EntryPoint struct {
	Kind    string `json:"kind"`
	Line    int    `json:"line"` // 1-based
	Summary string `json:"summary"`
}

const (
	// maxEntryScanBytes bounds how much of a file is examined; a bigger file is
	// scanned up to this point and the rest is ignored.
	maxEntryScanBytes = 1 << 20
	// maxEntryLineLen skips minified or generated lines, where the patterns are
	// both slow and meaningless.
	maxEntryLineLen = 1000
	// MaxEntryPoints bounds how many hints one file yields.
	MaxEntryPoints = 40
	// maxSummaryLen bounds a hint's summary.
	maxSummaryLen = 100
)

// DetectEntryPoints returns the entry-point hints found in one file's source,
// ordered by line. name selects the language by extension (unknown languages yield
// nothing). It performs no I/O and looks at nothing but src, so it cannot make a
// claim about any other file.
//
// Summaries carry only the kind of entry point, an HTTP method and a route path
// literal (bounded and scrubbed of anything token-like) — never arguments, bodies
// or other source text.
func DetectEntryPoints(name string, src []byte) []EntryPoint {
	lang := entryLang(name)
	if lang == "" {
		return nil
	}
	if len(src) > maxEntryScanBytes {
		src = src[:maxEntryScanBytes]
	}
	rules := entryRules[lang]
	if rules == nil {
		return nil
	}

	var out []EntryPoint
	seen := map[string]bool{}
	grpcFile := lang == "go" && grpcFileRE.Match(src)
	inBlockComment := false

	lineNo := 0
	for _, raw := range bytes.Split(src, []byte("\n")) {
		lineNo++
		if len(raw) > maxEntryLineLen {
			continue
		}
		line := string(raw)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Skip comment-only lines: a commented-out route is not an entry point.
		if inBlockComment {
			if strings.Contains(trimmed, "*/") {
				inBlockComment = false
			}
			continue
		}
		if strings.HasPrefix(trimmed, "/*") {
			inBlockComment = !strings.Contains(trimmed, "*/")
			continue
		}
		if isLineComment(lang, trimmed) {
			continue
		}

		for _, r := range rules {
			m := r.re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if r.deny != nil && r.deny(m) {
				continue
			}
			summary := r.summary(m)
			if len(summary) > maxSummaryLen {
				summary = summary[:maxSummaryLen-3] + "..."
			}
			// One hint per distinct thing: a file reading os.Args five times is
			// one CLI entry point, not five.
			key := r.kind + "|" + summary
			if r.once {
				key = r.kind + "|" + r.group
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, EntryPoint{Kind: r.kind, Line: lineNo, Summary: summary})
			if len(out) >= MaxEntryPoints {
				return out
			}
		}

		if grpcFile {
			if m := goGRPCMethodRE.FindStringSubmatch(line); m != nil {
				summary := "gRPC method " + m[1]
				if !seen[KindGRPC+"|"+summary] {
					seen[KindGRPC+"|"+summary] = true
					out = append(out, EntryPoint{Kind: KindGRPC, Line: lineNo, Summary: summary})
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

// entryLang maps a file name to the language family the rules are keyed on.
func entryLang(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx":
		return "js"
	case ".java", ".kt", ".kts":
		return "java"
	case ".rb":
		return "ruby"
	case ".php":
		return "php"
	}
	return ""
}

func isLineComment(lang, trimmed string) bool {
	switch lang {
	case "go", "js", "java":
		return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*")
	case "python", "ruby":
		return strings.HasPrefix(trimmed, "#")
	case "php":
		return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*")
	}
	return false
}

type entryRule struct {
	kind    string
	re      *regexp.Regexp
	summary func(m []string) string
	deny    func(m []string) bool // optional: reject a match (e.g. an HTTP client, not a router)
	// once makes this rule emit a single hint per `group` per file.
	once  bool
	group string
}

func rule(kind, pattern string, summary func(m []string) string) entryRule {
	return entryRule{kind: kind, re: regexp.MustCompile(pattern), summary: summary}
}

func fixed(s string) func([]string) string { return func([]string) string { return s } }

// route renders "HTTP route [METHOD ]path" from the matched method (may be "") and
// path literal.
func route(method, path string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	p := safePath(path)
	if method == "" {
		return "HTTP route " + p
	}
	return "HTTP route " + method + " " + p
}

var pathOK = regexp.MustCompile(`^[A-Za-z0-9_\-./:{}<>*$?%@+=,~!&|\[\]^() ]*$`)

// safePath bounds and scrubs a route literal so a hint can never carry a secret:
// anything with unexpected characters becomes "(dynamic)", and any long
// token-looking segment is masked.
func safePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !pathOK.MatchString(p) {
		return "(dynamic)"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if len(s) >= 20 && !strings.ContainsAny(s, "{}<>:*$") {
			segs[i] = "*"
		}
	}
	p = strings.Join(segs, "/")
	if len(p) > 60 {
		p = p[:57] + "..."
	}
	return p
}

var (
	grpcFileRE     = regexp.MustCompile(`Unimplemented\w+Server|Register\w+Server\(`)
	goGRPCMethodRE = regexp.MustCompile(`^func \(\w+ \*?\w+\) (\w+)\(\w+ context\.Context, \w+ \*?[\w.]+\) \(\*?[\w.]+, error\)`)

	httpVerbs = `(?i:get|post|put|delete|patch|head|options)`

	// routerReceiver limits gin/echo/chi/express-style matches to receiver names
	// that look like routers or apps, so `axios.get('/x')`, `api.get('/x')` or
	// `cache.Get("/k")` are not reported as routes. A router under an unusual name
	// is missed: that is the safe direction for a hint.
	routerReceiver = regexp.MustCompile(`(?i)^(app|server|srv|router|routes?|fastify|koa|mux|group|engine|r|e|g|rg|v\d+|\w*router|\w*app|\w*routes?|\w*server|\w*mux|\w*group)$`)
)

var entryRules = map[string][]entryRule{
	"go": {
		rule(KindHTTPRoute, `\b\w+\.(?:HandleFunc|Handle)\(\s*"([^"]*)"`, func(m []string) string {
			// Go 1.22 patterns may carry the method: "POST /x".
			if meth, p, ok := strings.Cut(m[1], " "); ok && httpVerbRE.MatchString(meth) {
				return route(meth, p)
			}
			return route("", m[1])
		}),
		{kind: KindHTTPRoute, re: regexp.MustCompile(`\b(\w+)\.(` + httpVerbs + `)\(\s*"(/[^"]*)"`),
			summary: func(m []string) string { return route(m[2], m[3]) },
			deny:    func(m []string) bool { return !routerReceiver.MatchString(m[1]) }},
		rule(KindGRPC, `\bRegister(\w+)Server\(`, func(m []string) string { return "gRPC service " + m[1] + " registered" }),
		{kind: KindCLI, re: regexp.MustCompile(`\bos\.Args\b|\bflag\.(?:Parse|NewFlagSet)\(`),
			summary: fixed("command-line arguments"), once: true, group: "cli"},
		{kind: KindConsumer, re: regexp.MustCompile(`\bos\.Stdin\b`),
			summary: fixed("reads standard input"), once: true, group: "stdin"},
		rule(KindConsumer, `\.(Consume|Subscribe|ReceiveMessage|ReadMessage|FetchMessage)\(`,
			func(m []string) string { return "message consumer (" + m[1] + ")" }),
		rule(KindConsumer, `\bfsnotify\.NewWatcher\(`, fixed("file watcher")),
	},
	"python": {
		rule(KindHTTPRoute, `^\s*@\w+(?:\.\w+)*\.route\(\s*['"]([^'"]*)['"](?:.*methods\s*=\s*[\[(]([^\])]*)[\])])?`,
			func(m []string) string {
				return route(strings.NewReplacer("'", "", `"`, "", " ", "").Replace(m[2]), m[1])
			}),
		rule(KindHTTPRoute, `^\s*@\w+(?:\.\w+)*\.(`+httpVerbs+`|api_route)\(\s*['"]([^'"]*)['"]`,
			func(m []string) string {
				if strings.EqualFold(m[1], "api_route") {
					return route("", m[2])
				}
				return route(m[1], m[2])
			}),
		rule(KindHTTPRoute, `^\s*(?:path|re_path|url)\(\s*r?['"]([^'"]*)['"]`,
			func(m []string) string { return "Django URL pattern " + safePath(m[1]) }),
		rule(KindHTTPRoute, `^\s*class\s+(\w+)\((?:[\w.]*\.)?(?:View|APIView|ViewSet|ModelViewSet|GenericAPIView|ListAPIView|CreateAPIView)\)`,
			func(m []string) string { return "Django view class " + m[1] }),
		{kind: KindCLI, re: regexp.MustCompile(`\bargparse\.ArgumentParser\(|\bsys\.argv\b|^\s*@click\.(?:command|group)\b|\btyper\.Typer\(`),
			summary: fixed("command-line arguments"), once: true, group: "cli"},
		rule(KindConsumer, `^\s*@(?:\w+\.)?(?:task|shared_task)\b|\bKafkaConsumer\(|\.basic_consume\(`,
			fixed("task / message-queue consumer")),
		rule(KindConsumer, `\bFileSystemEventHandler\b|\bObserver\(\)`, fixed("file watcher")),
		{kind: KindConsumer, re: regexp.MustCompile(`\bsys\.stdin\b`),
			summary: fixed("reads standard input"), once: true, group: "stdin"},
	},
	"js": {
		{kind: KindHTTPRoute, re: regexp.MustCompile("\\b(\\w+)\\.(" + httpVerbs + "|all|use)\\(\\s*['\"`](/[^'\"`]*)['\"`]"),
			summary: func(m []string) string {
				meth := m[2]
				if strings.EqualFold(meth, "use") || strings.EqualFold(meth, "all") {
					meth = ""
				}
				return route(meth, m[3])
			},
			deny: func(m []string) bool { return !routerReceiver.MatchString(m[1]) }},
		rule(KindHTTPRoute, "\\.route\\(\\s*['\"`](/[^'\"`]*)['\"`]\\s*\\)", func(m []string) string { return route("", m[1]) }),
		rule(KindHTTPRoute, `^\s*@(Get|Post|Put|Delete|Patch|Head|Options)\(\s*(?:['"]([^'"]*)['"])?\s*\)`,
			func(m []string) string { return route(m[1], "/"+strings.TrimPrefix(m[2], "/")) }),
		rule(KindHTTPRoute, `^\s*export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(`,
			func(m []string) string { return "Next.js route handler " + m[1] }),
		{kind: KindCLI, re: regexp.MustCompile(`\bprocess\.argv\b|\byargs\b|\brequire\(\s*['"]commander['"]\s*\)`),
			summary: fixed("command-line arguments"), once: true, group: "cli"},
		rule(KindConsumer, `\.on\(\s*['"](message|connection)['"]`,
			func(m []string) string { return "event handler for '" + m[1] + "' (websocket / queue)" }),
		rule(KindConsumer, `\bconsumer\.(?:run|subscribe)\(|\.receiveMessage\(|\bchokidar\.watch\(`,
			fixed("message / file consumer")),
		{kind: KindConsumer, re: regexp.MustCompile(`\bprocess\.stdin\b`),
			summary: fixed("reads standard input"), once: true, group: "stdin"},
	},
	"java": {
		rule(KindHTTPRoute, `@(Get|Post|Put|Delete|Patch)Mapping\b(?:\(([^)]*)\))?`,
			func(m []string) string { return route(m[1], javaMappingPath(m[2])) }),
		rule(KindHTTPRoute, `@RequestMapping\b(?:\(([^)]*)\))?`, func(m []string) string {
			return route(javaRequestMethod(m[1]), javaMappingPath(m[1]))
		}),
		rule(KindHTTPRoute, `@Path\(\s*"([^"]*)"`, func(m []string) string { return route("", m[1]) }),
		rule(KindHTTPRoute, `\b(?:void|fun)\s+do(Get|Post|Put|Delete|Head|Options)\s*\(`,
			func(m []string) string { return "servlet handler do" + m[1] }),
		rule(KindConsumer, `@(Kafka|Rabbit|Jms|Sqs)Listener\b`,
			func(m []string) string { return m[1] + " message listener" }),
		{kind: KindCLI, re: regexp.MustCompile(`\bstatic\s+void\s+main\s*\(\s*String|\bfun\s+main\s*\(\s*args`),
			summary: fixed("command-line arguments (main)"), once: true, group: "cli"},
	},
	"ruby": {
		rule(KindHTTPRoute, `^\s*(get|post|put|patch|delete|match)\s+['"]([^'"]*)['"]`,
			func(m []string) string {
				if m[1] == "match" {
					return route("", m[2])
				}
				return route(m[1], m[2])
			}),
		rule(KindHTTPRoute, `^\s*resources?\s+:(\w+)`, func(m []string) string { return "Rails resource routes :" + m[1] }),
		rule(KindHTTPRoute, `^\s*class\s+(\w+Controller)\s*<`, func(m []string) string { return "Rails controller " + m[1] }),
		{kind: KindRequest, re: regexp.MustCompile(`\bparams\s*(?:\[|\.(?:require|permit|fetch)\b)`),
			summary: fixed("reads request params"), once: true, group: "params"},
		{kind: KindCLI, re: regexp.MustCompile(`\bARGV\b|\bOptionParser\.new\b|<\s*Thor\b`),
			summary: fixed("command-line arguments"), once: true, group: "cli"},
	},
	"php": {
		rule(KindRequest, `\$_(GET|POST|REQUEST|COOKIE|FILES)\b`,
			func(m []string) string { return "reads $_" + m[1] + " (request input)" }),
		{kind: KindRequest, re: regexp.MustCompile(`\$_SERVER\s*\[\s*['"](?:HTTP_|REQUEST_URI|QUERY_STRING|PATH_INFO)`),
			summary: fixed("reads request headers / URI via $_SERVER"), once: true, group: "server"},
		{kind: KindRequest, re: regexp.MustCompile(`php://input`),
			summary: fixed("reads the raw request body"), once: true, group: "body"},
		rule(KindHTTPRoute, `\bRoute::(get|post|put|patch|delete|any|match)\(\s*['"]([^'"]*)['"]`,
			func(m []string) string {
				if m[1] == "any" || m[1] == "match" {
					return route("", m[2])
				}
				return route(m[1], m[2])
			}),
		{kind: KindCLI, re: regexp.MustCompile(`\$argv\b|\bgetopt\(`),
			summary: fixed("command-line arguments"), once: true, group: "cli"},
	},
}

var httpVerbRE = regexp.MustCompile(`^(?i:get|post|put|delete|patch|head|options)$`)

var (
	javaPathRE   = regexp.MustCompile(`(?:(?:value|path)\s*=\s*)?\{?\s*"([^"]*)"`)
	javaMethodRE = regexp.MustCompile(`RequestMethod\.(\w+)`)
)

func javaMappingPath(args string) string {
	if m := javaPathRE.FindStringSubmatch(args); m != nil {
		return m[1]
	}
	return "/"
}

func javaRequestMethod(args string) string {
	if m := javaMethodRE.FindStringSubmatch(args); m != nil {
		return m[1]
	}
	return ""
}
