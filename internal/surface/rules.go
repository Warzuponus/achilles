package surface

import (
	"bytes"
	"path"
	"regexp"
	"strings"

	"github.com/Warzuponus/achilles/internal/inventory"
)

// langOf maps a file to the language family the patterns are keyed on.
func langOf(rel string) string {
	switch strings.ToLower(path.Ext(rel)) {
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

// infraKind classifies deployment and CI files by name alone.
func infraKind(rel string) string {
	base := strings.ToLower(path.Base(rel))
	lower := strings.ToLower(rel)
	switch {
	case base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile"):
		return "dockerfile"
	case strings.HasPrefix(base, "docker-compose") || strings.HasPrefix(base, "compose.") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")):
		return "compose"
	case strings.HasSuffix(base, ".tf"):
		return "terraform"
	case base == "chart.yaml":
		return "helm"
	case (strings.HasPrefix(lower, ".github/workflows/") || strings.Contains(lower, "/.github/workflows/")) &&
		(strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")):
		return "ci-workflow"
	case base == ".gitlab-ci.yml" || base == "jenkinsfile" || base == "azure-pipelines.yml":
		return "ci-workflow"
	}
	return ""
}

var (
	k8sKindRE = regexp.MustCompile(`(?m)^kind:\s*(Deployment|StatefulSet|DaemonSet|Pod|Service|Ingress|Job|CronJob|Role|ClusterRole|RoleBinding|ClusterRoleBinding|NetworkPolicy|ServiceAccount)\s*$`)
	k8sAPIRE  = regexp.MustCompile(`(?m)^apiVersion:\s*\S+`)
)

func isKubernetes(src []byte) bool {
	return k8sAPIRE.Match(src) && k8sKindRE.Match(src)
}

// pattern is one line-level hint.
type pattern struct {
	kind, class, summary string
	re                   *regexp.Regexp
}

func p(kind, class, summary, re string) pattern {
	return pattern{kind: kind, class: class, summary: summary, re: regexp.MustCompile(re)}
}

// Patterns shared by every language. They are deliberately coarse: a missed
// control only moves a file up the review order, and a missed sink only moves it
// down, never out.
var common = []pattern{
	// Controls.
	p(KindControl, "authn", "authentication check",
		`(?i)(\b(login_required|requires?_auth\w*|is_?authenticated|authenticate_user!|passport\.authenticate|AuthGuard|before_action\s+:authenticate\w*|require_login|verify_jwt\w*|jwt\.(verify|decode|Parse\w*)|auth_?middleware|requireAuth\w*|ensureAuth\w*|IsAuthenticated)\b|@(PreAuthorize|Secured|RolesAllowed|UseGuards|authenticated)\b)`),
	p(KindControl, "authz", "authorization check",
		`(?i)\b(permission_required|has_?permission\w*|authorize\w*|check_?permission\w*|policy_scope|hasRole|hasAuthority|require_role\w*|is_admin|isAdmin)\b`),
	p(KindControl, "csrf", "CSRF protection", `(?i)\b(csrf\w*|csurf|xsrf\w*|protect_from_forgery|CsrfViewMiddleware)\b`),
	p(KindControl, "validation", "input validation or escaping",
		`(?i)\b(validat\w*|sanitiz\w*|bleach\.clean|html\.EscapeString|escapeHtml|DOMPurify|zod\.|z\.object|Joi\.|pydantic|filter_var|htmlspecialchars|strip_tags|ParameterizedQuery|shlex\.quote|escapeshellarg)\b|@Valid\b`),
	p(KindControl, "rate-limit", "rate limiting", `(?i)\b(rate_?limit\w*|ratelimit\w*|throttl\w*|limiter)\b`),
	// Assets.
	p(KindAsset, "credentials", "handles credentials",
		`(?i)\b(password|passwd|passphrase|secret_?key|api_?key|private_?key|access_?token|refresh_?token|client_?secret)\b`),
	p(KindAsset, "personal-data", "handles personal data",
		`(?i)\b(ssn|social_?security\w*|date_?of_?birth|credit_?card\w*|card_?number|iban|passport_?number|tax_?id)\b`),
	p(KindAsset, "session", "handles sessions or tokens",
		`(?i)\b(set_?cookie|setcookie|session_?id|jwt\.sign|SignedString|create_?access_?token|express-session|cookie-session)\b`),
	// AI surface.
	p(KindAI, "llm-sdk", "calls an LLM API",
		`(?i)(\bimport\s+openai\b|\bfrom\s+openai\b|\bimport\s+anthropic\b|\bfrom\s+anthropic\b|['"]openai['"]|@anthropic-ai/sdk|google\.generativeai|google\.genai|\blangchain\w*|\bllama_?index\b|\bollama\b|chat\.completions\.create|messages\.create\(|ChatCompletion\b|ChatOpenAI|ChatAnthropic|\bgenerateText\(|\bstreamText\()`),
	p(KindAI, "tool-calling", "exposes tools to a model",
		`(?i)(\btool_choice\b|\bbind_tools\(|\bfunction_call\b|^\s*@tool\b|\btools\s*=\s*\[|\bStructuredTool\b|\bAgentExecutor\b|create_\w*agent\(|\bcreateReactAgent\b)`),
	p(KindAI, "mcp", "MCP server or client",
		`(?i)(@modelcontextprotocol/|\bFastMCP\b|\bMcpServer\b|\bmcp\.server\b|from\s+mcp\b|import\s+mcp\b|@mcp\.tool|server\.tool\(|\bmcp-go\b|mark3labs/mcp)`),
	p(KindAI, "vector-store", "vector store or embeddings",
		`(?i)\b(chromadb|chromem|pinecone|weaviate|qdrant|faiss|pgvector|milvus|embeddings?\.create|OpenAIEmbeddings|VectorStore\w*)\b`),
	p(KindAI, "prompt", "builds prompts from data",
		`(?i)\b(PromptTemplate|ChatPromptTemplate|system_prompt|systemPrompt|SystemMessage|HumanMessage)\b`),
}

// Sinks per language family.
var sinks = map[string][]pattern{
	"go": {
		p(KindSink, "sql", "SQL execution", `\.(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw)\(`),
		p(KindSink, "exec", "runs a program", `\bexec\.Command(Context)?\(`),
		p(KindSink, "file", "file access", `\bos\.(Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll)\(|\bhttp\.ServeFile\(`),
		p(KindSink, "ssrf", "outbound request", `\bhttp\.(Get|Post|Head|NewRequest\w*)\(|\.Do\(req\)`),
		p(KindSink, "template", "unescaped HTML", `\btemplate\.(HTML|JS|URL)\(`),
		p(KindSink, "redirect", "redirect", `\bhttp\.Redirect\(`),
		p(KindSink, "deserialize", "decodes untyped data", `\bgob\.NewDecoder\(|\byaml\.Unmarshal\(`),
	},
	"python": {
		p(KindSink, "sql", "SQL execution", `\.(execute|executemany|executescript|raw)\(|\btext\(\s*f?["']`),
		p(KindSink, "exec", "runs a program", `\bsubprocess\.\w+\(|\bos\.(system|popen|exec\w*|spawn\w*)\(`),
		p(KindSink, "eval", "evaluates code", `(^|[^.\w])(eval|exec)\(`),
		p(KindSink, "deserialize", "deserialization", `\b(pickle|cPickle|marshal|dill|shelve)\.loads?\(|\byaml\.load\(|\bjsonpickle\.decode\(`),
		p(KindSink, "file", "file access", `(^|[^.\w])open\(|\bsend_file\(|\bsend_from_directory\(|\bos\.(remove|unlink)\(|\bshutil\.\w+\(`),
		p(KindSink, "ssrf", "outbound request", `\brequests\.(get|post|put|delete|request|head)\(|\burlopen\(|\bhttpx\.\w+\(|\burllib3\.`),
		p(KindSink, "template", "unescaped HTML", `\brender_template_string\(|\bMarkup\(|\bmark_safe\(|\|\s*safe\b`),
		p(KindSink, "redirect", "redirect", `\bredirect\(`),
	},
	"js": {
		p(KindSink, "sql", "SQL execution", `\.(query|raw|\$queryRaw\w*|\$executeRaw\w*)\(|\bsequelize\.query\(|\bknex\.raw\(`),
		p(KindSink, "exec", "runs a program", `\bchild_process\b|(^|[^.\w])(exec|execSync|execFile|execFileSync|spawn|spawnSync)\(`),
		p(KindSink, "eval", "evaluates code", `(^|[^.\w])eval\(|\bnew Function\(|\bvm\.run\w*\(`),
		p(KindSink, "file", "file access", `\bfs\.(readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rm|rmSync)\(|\.sendFile\(|\.download\(`),
		p(KindSink, "ssrf", "outbound request", `(^|[^.\w])fetch\(|\baxios(\.\w+)?\(|\bhttps?\.(get|request)\(|\bgot\(`),
		p(KindSink, "template", "unescaped HTML", `\.innerHTML\s*=|\bdangerouslySetInnerHTML\b|\bdocument\.write\(|\.html\(\s*[^)]`),
		p(KindSink, "redirect", "redirect", `\.redirect\(`),
		p(KindSink, "deserialize", "deserialization", `\bunserialize\(|\bnode-serialize\b|\byaml\.load\(`),
	},
	"java": {
		p(KindSink, "sql", "SQL execution", `\.(executeQuery|executeUpdate|execute|addBatch|createQuery|createNativeQuery|queryForObject|queryForList)\(|\bjdbcTemplate\.(query|update)\w*\(`),
		p(KindSink, "exec", "runs a program", `\bRuntime\.getRuntime\(\)\.exec\(|\bnew ProcessBuilder\(`),
		p(KindSink, "deserialize", "deserialization", `\bnew ObjectInputStream\(|\.readObject\(|\bXMLDecoder\b|\bnew Yaml\(\)`),
		p(KindSink, "file", "file access", `\bnew File(InputStream|OutputStream|Reader|Writer)?\(|\bFiles\.(read\w*|write\w*|newInputStream|newOutputStream|delete\w*)\(|\bPaths\.get\(`),
		p(KindSink, "ssrf", "outbound request", `\bnew URL\(|\bHttpClient\b|\bRestTemplate\b|\bWebClient\b|\bopenConnection\(`),
		p(KindSink, "xml", "XML parsing", `\bDocumentBuilderFactory\b|\bSAXParserFactory\b|\bXMLInputFactory\b`),
		p(KindSink, "redirect", "redirect", `\.sendRedirect\(`),
	},
	"ruby": {
		p(KindSink, "sql", "SQL execution", `\.(find_by_sql|execute|exec_query|select_all|where)\(\s*["']|\.(order|group|pluck)\(\s*params`),
		p(KindSink, "exec", "runs a program", "(^|[^.\\w])(system|exec|spawn)\\(|`[^`]*#\\{|%x[({]|\\bOpen3\\.|\\bIO\\.popen\\("),
		p(KindSink, "eval", "evaluates code", `(^|[^.\w])(eval|instance_eval|class_eval)\(|\.(send|public_send)\(\s*params`),
		p(KindSink, "deserialize", "deserialization", `\bMarshal\.load\(|\bYAML\.(load|unsafe_load)\(`),
		p(KindSink, "file", "file access", `\bFile\.(open|read|write|delete)\(|\bsend_file\(|\bIO\.read\(`),
		p(KindSink, "ssrf", "outbound request", `\bNet::HTTP\b|\bopen-uri\b|\bURI\.open\(|\bHTTParty\b|\bFaraday\b`),
		p(KindSink, "template", "unescaped HTML", `\.html_safe\b|(^|[^.\w])raw\(`),
		p(KindSink, "redirect", "redirect", `\bredirect_to\(?\s*params`),
	},
	"php": {
		p(KindSink, "sql", "SQL execution", `\b(mysqli_query|mysql_query|pg_query|sqlite_query)\(|->(query|exec|prepare)\(|\bDB::(select|statement|raw)\(`),
		p(KindSink, "exec", "runs a program", "\\b(shell_exec|exec|system|passthru|popen|proc_open|pcntl_exec)\\(|`[^`]*\\$"),
		p(KindSink, "eval", "evaluates code", `\b(eval|assert|create_function)\(|preg_replace\(\s*['"].*/e['"]`),
		p(KindSink, "deserialize", "deserialization", `\bunserialize\(`),
		p(KindSink, "file", "file access", `\b(file_get_contents|file_put_contents|fopen|readfile|unlink|move_uploaded_file)\(|\b(include|require)(_once)?\s*\(?\s*\$`),
		p(KindSink, "ssrf", "outbound request", `\bcurl_exec\(|\bcurl_init\(`),
		p(KindSink, "redirect", "redirect", `header\(\s*['"]Location:`),
	},
}

// scanFile returns the facts in one source file: the inventory's entry points,
// then one fact per pattern class per file (the first line it matches on), so a
// file with fifty queries is one SQL sink, not fifty.
func scanFile(rel, lang string, src []byte) []Fact {
	var out []Fact
	for _, ep := range inventory.DetectEntryPoints(rel, src) {
		out = append(out, Fact{Kind: KindEntry, Class: ep.Kind, File: rel, Line: ep.Line, Summary: ep.Summary})
	}
	pats := append(append([]pattern(nil), sinks[lang]...), common...)
	seen := map[string]bool{}
	lineNo := 0
	inBlock := false
	for _, raw := range bytes.Split(src, []byte("\n")) {
		lineNo++
		if len(raw) > 1000 {
			continue // minified or generated
		}
		line := string(raw)
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if inBlock {
			if strings.Contains(t, "*/") {
				inBlock = false
			}
			continue
		}
		if strings.HasPrefix(t, "/*") {
			inBlock = !strings.Contains(t, "*/")
			continue
		}
		if isComment(lang, t) {
			continue
		}
		for _, pt := range pats {
			key := pt.kind + "|" + pt.class
			if seen[key] || !pt.re.MatchString(line) {
				continue
			}
			seen[key] = true
			out = append(out, Fact{Kind: pt.kind, Class: pt.class, File: rel, Line: lineNo, Summary: pt.summary})
		}
	}
	return out
}

func isComment(lang, t string) bool {
	switch lang {
	case "go", "js", "java":
		return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*")
	case "python", "ruby":
		return strings.HasPrefix(t, "#")
	case "php":
		return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "*")
	}
	return false
}
