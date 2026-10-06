package inventory

import (
	"fmt"
	"strings"
	"testing"
)

func summaries(eps []EntryPoint) []string {
	var out []string
	for _, e := range eps {
		out = append(out, fmt.Sprintf("%d:%s:%s", e.Line, e.Kind, e.Summary))
	}
	return out
}

// has reports whether some hint has this kind and a summary containing sub.
func has(eps []EntryPoint, kind, sub string) bool {
	for _, e := range eps {
		if e.Kind == kind && strings.Contains(e.Summary, sub) {
			return true
		}
	}
	return false
}

func TestDetectEntryPoints_ByLanguage(t *testing.T) {
	cases := []struct {
		name, file, src string
		kind, want      string
		line            int
	}{
		{"go handlefunc", "a.go", "package a\nfunc main() {\n\thttp.HandleFunc(\"/upload\", up)\n}\n", KindHTTPRoute, "HTTP route /upload", 3},
		{"go 1.22 method pattern", "a.go", "mux.HandleFunc(\"POST /x\", h)\n", KindHTTPRoute, "HTTP route POST /x", 1},
		{"go gin", "a.go", "r.GET(\"/users/:id\", h)\n", KindHTTPRoute, "HTTP route GET /users/:id", 1},
		{"go chi", "a.go", "r.Post(\"/items\", h)\n", KindHTTPRoute, "HTTP route POST /items", 1},
		{"go grpc register", "a.go", "pb.RegisterBillingServer(s, &srv{})\n", KindGRPC, "gRPC service Billing", 1},
		{"go os.Args", "a.go", "x := os.Args[1]\n", KindCLI, "command-line", 1},
		{"go stdin", "a.go", "sc := bufio.NewScanner(os.Stdin)\n", KindConsumer, "standard input", 1},
		{"go consumer", "a.go", "msgs, _ := ch.Consume(q)\n", KindConsumer, "message consumer", 1},
		{"flask route", "a.py", "@app.route('/login', methods=['POST', 'GET'])\ndef login():\n", KindHTTPRoute, "HTTP route POST,GET /login", 1},
		{"fastapi", "a.py", "@router.post(\"/pay\")\n", KindHTTPRoute, "HTTP route POST /pay", 1},
		{"django url", "urls.py", "urlpatterns = [\n    path('admin/', x),\n]\n", KindHTTPRoute, "Django URL pattern admin/", 2},
		{"python argparse", "a.py", "p = argparse.ArgumentParser()\n", KindCLI, "command-line", 1},
		{"celery", "a.py", "@shared_task\ndef run(): pass\n", KindConsumer, "consumer", 1},
		{"express", "a.js", "app.post('/api/x', (req, res) => {})\n", KindHTTPRoute, "HTTP route POST /api/x", 1},
		{"koa router", "a.ts", "router.get(`/health`, ctx => {})\n", KindHTTPRoute, "HTTP route GET /health", 1},
		{"fastify", "a.ts", "fastify.get('/v', handler)\n", KindHTTPRoute, "HTTP route GET /v", 1},
		{"nest", "a.ts", "  @Post('login')\n", KindHTTPRoute, "HTTP route POST /login", 1},
		{"next route", "route.ts", "export async function POST(req: Request) {}\n", KindHTTPRoute, "Next.js route handler POST", 1},
		{"node argv", "a.js", "const a = process.argv.slice(2)\n", KindCLI, "command-line", 1},
		{"ws message", "a.js", "ws.on('message', m => {})\n", KindConsumer, "'message'", 1},
		{"spring get", "A.java", "    @GetMapping(\"/users/{id}\")\n", KindHTTPRoute, "HTTP route GET /users/{id}", 1},
		{"spring request mapping method", "A.java", "@RequestMapping(value = \"/x\", method = RequestMethod.POST)\n", KindHTTPRoute, "HTTP route POST /x", 1},
		{"servlet", "A.java", "protected void doPost(HttpServletRequest r) {\n", KindHTTPRoute, "servlet handler doPost", 1},
		{"kotlin servlet", "A.kt", "override fun doGet(r: HttpServletRequest) {\n", KindHTTPRoute, "servlet handler doGet", 1},
		{"kafka listener", "A.java", "@KafkaListener(topics = \"t\")\n", KindConsumer, "Kafka message listener", 1},
		{"java main", "A.java", "public static void main(String[] args) {\n", KindCLI, "main", 1},
		{"rails route", "routes.rb", "Rails.application.routes.draw do\n  post '/sessions', to: 'sessions#create'\nend\n", KindHTTPRoute, "HTTP route POST /sessions", 2},
		{"rails controller", "a_controller.rb", "class UsersController < ApplicationController\n", KindHTTPRoute, "Rails controller UsersController", 1},
		{"rails params", "a.rb", "name = params[:name]\n", KindRequest, "request params", 1},
		{"php superglobal", "a.php", "<?php\n$id = $_GET['id'];\n", KindRequest, "$_GET", 2},
		{"laravel", "web.php", "Route::post('/orders', [C::class, 'store']);\n", KindHTTPRoute, "HTTP route POST /orders", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eps := DetectEntryPoints(tc.file, []byte(tc.src))
			if !has(eps, tc.kind, tc.want) {
				t.Fatalf("want %s containing %q, got %v", tc.kind, tc.want, summaries(eps))
			}
			for _, e := range eps {
				if e.Kind == tc.kind && strings.Contains(e.Summary, tc.want) && e.Line != tc.line {
					t.Errorf("line = %d, want %d", e.Line, tc.line)
				}
			}
		})
	}
}

func TestDetectEntryPoints_GRPCMethodNeedsAGRPCFile(t *testing.T) {
	method := "func (s *srv) Charge(ctx context.Context, in *pb.Req) (*pb.Resp, error) {\n"
	if eps := DetectEntryPoints("a.go", []byte(method)); len(eps) != 0 {
		t.Errorf("a plain ctx method is not a gRPC method without a gRPC registration: %v", summaries(eps))
	}
	grpc := "type srv struct{ pb.UnimplementedBillingServer }\n" + method
	if eps := DetectEntryPoints("a.go", []byte(grpc)); !has(eps, KindGRPC, "gRPC method Charge") {
		t.Errorf("gRPC method not found: %v", summaries(eps))
	}
}

func TestDetectEntryPoints_NoFalseRoutes(t *testing.T) {
	src := "resp, _ := http.Get(\"/x\")\n" + // an HTTP client, not a router
		"v := cache.Get(\"/key\")\n" +
		"// http.HandleFunc(\"/commented\", h)\n" +
		"/*\nhttp.HandleFunc(\"/block\", h)\n*/\n"
	if eps := DetectEntryPoints("a.go", []byte(src)); len(eps) != 0 {
		t.Errorf("expected no hints, got %v", summaries(eps))
	}
	js := "axios.get('/api/x')\ncache.get('/k')\n$.post('/y')\n"
	if eps := DetectEntryPoints("a.js", []byte(js)); len(eps) != 0 {
		t.Errorf("HTTP clients are not routes: %v", summaries(eps))
	}
	if eps := DetectEntryPoints("a.txt", []byte("http.HandleFunc(\"/x\", h)")); eps != nil {
		t.Errorf("unknown language should yield nothing, got %v", eps)
	}
}

func TestDetectEntryPoints_DedupesRepeatedCLIUse(t *testing.T) {
	src := "a := os.Args[1]\nb := os.Args[2]\nflag.Parse()\n"
	eps := DetectEntryPoints("a.go", []byte(src))
	if len(eps) != 1 || eps[0].Line != 1 {
		t.Errorf("one CLI hint at the first use, got %v", summaries(eps))
	}
}

func TestDetectEntryPoints_NeverCarriesSecretsOrCode(t *testing.T) {
	secret := "sk_live_ABCDEFGHIJKLMNOPQRSTUVWX1234"
	src := "http.HandleFunc(\"/hook/" + secret + "\", h)\n" +
		"app.get('/a b\"; token=" + secret + "', h)\n"
	eps := DetectEntryPoints("a.go", []byte(src))
	js := DetectEntryPoints("a.js", []byte(src))
	for _, e := range append(eps, js...) {
		if strings.Contains(e.Summary, secret) || strings.Contains(e.Summary, "sk_live") {
			t.Errorf("secret leaked into hint: %q", e.Summary)
		}
	}
	if len(eps) == 0 || !strings.Contains(eps[0].Summary, "/hook/*") {
		t.Errorf("token-like segment should be masked, got %v", summaries(eps))
	}
}

func TestDetectEntryPoints_Bounded(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, "http.HandleFunc(\"/r%d\", h)\n", i)
	}
	if eps := DetectEntryPoints("a.go", []byte(b.String())); len(eps) != MaxEntryPoints {
		t.Errorf("hints = %d, want cap %d", len(eps), MaxEntryPoints)
	}
	// A giant single line (minified bundle) is skipped, not scanned.
	long := "app.get('/x', h);" + strings.Repeat("a", maxEntryLineLen+1)
	if eps := DetectEntryPoints("a.js", []byte(long)); len(eps) != 0 {
		t.Errorf("over-long line should be skipped, got %v", summaries(eps))
	}
}
