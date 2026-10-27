#!/usr/bin/env python3
"""Render docs/*.md into a single self-contained docs/site.html.

Usage: python3 docs/build.py   (or `make docs-html`)
Requires: pip install markdown   (only to BUILD; the output is dependency-free).

The output is one styled page with a sidebar; sibling `guide.md` links become
in-page anchors, and `../path` links stay relative (they resolve from docs/ in a
checkout). Matches the Achilles HTML report's look; light/dark aware.
"""
import os
import re
import sys

try:
    import markdown
except ImportError:
    sys.exit("needs the 'markdown' package: pip install markdown")

HERE = os.path.dirname(os.path.abspath(__file__))

# When hosting the page elsewhere, `../repo` links can't resolve — set this to a repo
# blob base (e.g. https://github.com/Warzuponus/achilles/blob/main) to rewrite them
# to absolute URLs. Unset (local/committed build) keeps them relative.
REPO_URL = os.environ.get("ACHILLES_DOCS_REPO_URL", "").rstrip("/")
PARENT_LINK = re.compile(r"\]\(\.\./([^)]+)\)")

# Order + sidebar labels. Slug = filename stem = section id + anchor.
GUIDES = [
    ("getting-started", "Getting Started"),
    ("cli-reference", "CLI Reference"),
    ("reports-and-gating", "Reports & Gating"),
    ("llm-and-agents", "LLM Triage & Agents"),
    ("deep-verify", "Deep Verification"),
    ("surface-map", "Surface Map & Scan Plan"),
    ("verifying-fixes", "Verifying Fixes"),
    ("benchmarking", "Benchmarking Detection"),
    ("comparison", "Comparison with Other Tools"),
    ("ci-and-hub", "CI & the Scan Hub"),
    ("fleet", "Fleet"),
    ("containers", "Running in Containers"),
    ("mcp", "MCP Server"),
]

SIBLING_LINK = re.compile(r"\]\((?!\.\.?/|https?://)([a-z0-9-]+)\.md(#[^)]*)?\)")


def render(slug):
    with open(os.path.join(HERE, f"{slug}.md")) as f:
        text = f.read()
    # Drop the leading H1 (the sidebar already names each guide).
    text = re.sub(r"\A#\s+.*\n", "", text, count=1)
    # Sibling guide links -> in-page anchors (drop any trailing #frag).
    text = SIBLING_LINK.sub(lambda m: f"](#{m.group(1)})", text)
    # ../repo links -> absolute repo URLs when hosting (else left relative).
    if REPO_URL:
        text = PARENT_LINK.sub(lambda m: f"]({REPO_URL}/{m.group(1)})", text)
    md = markdown.Markdown(extensions=["tables", "fenced_code", "sane_lists", "attr_list"])
    return md.convert(text)


def build():
    nav = "\n".join(
        f'<li><a href="#{slug}">{label}</a></li>' for slug, label in GUIDES
    )
    sections = "\n".join(
        f'<section id="{slug}"><h1>{label}</h1>\n{render(slug)}</section>'
        for slug, label in GUIDES
    )
    html = PAGE.replace("{{NAV}}", nav).replace("{{SECTIONS}}", sections)
    out = os.path.join(HERE, "site.html")
    with open(out, "w") as f:
        f.write(html)
    print(f"wrote {out} ({len(html)} bytes, {len(GUIDES)} guides)")


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Achilles — User Guides</title>
<style>
  :root{
    --bg:#0f1420; --panel:#171e2e; --panel2:#1e2740; --text:#e7ecf5; --muted:#93a0b8;
    --border:#2a3550; --accent:#7c9cff; --code:#0b0f1a;
  }
  @media (prefers-color-scheme: light){
    :root{ --bg:#f5f7fb; --panel:#fff; --panel2:#f0f3f9; --text:#111726; --muted:#5a6784;
      --border:#dde3ef; --accent:#3b5bdb; --code:#f3f5fa; }
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
    font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
  .layout{display:flex;max-width:1180px;margin:0 auto;gap:32px;padding:0 20px}
  nav{position:sticky;top:0;align-self:flex-start;height:100vh;overflow-y:auto;
    width:220px;flex:none;padding:28px 0}
  nav .brand{font-weight:800;font-size:18px;letter-spacing:-.02em;margin:0 0 4px}
  nav .tag{color:var(--muted);font-size:12px;margin:0 0 18px}
  nav ul{list-style:none;margin:0;padding:0}
  nav li a{display:block;padding:7px 12px;color:var(--muted);text-decoration:none;
    border-radius:8px;font-size:14px}
  nav li a:hover{background:var(--panel);color:var(--text)}
  main{flex:1;min-width:0;padding:28px 0 100px}
  section{border-bottom:1px solid var(--border);padding:8px 0 40px;margin-bottom:12px}
  section:last-child{border-bottom:none}
  h1{font-size:26px;letter-spacing:-.02em;margin:.2em 0 .6em;scroll-margin-top:20px}
  h2{font-size:20px;margin:1.4em 0 .5em;padding-top:.3em}
  h3{font-size:16px;margin:1.2em 0 .4em}
  h4{font-size:14px;color:var(--accent);text-transform:uppercase;letter-spacing:.04em;margin:1.1em 0 .3em}
  p,li{color:var(--text)}
  a{color:var(--accent)}
  blockquote{border-left:3px solid var(--accent);margin:1em 0;padding:.4em 0 .4em 16px;color:var(--muted)}
  code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;
    background:var(--panel2);border-radius:5px;padding:1px 6px}
  pre{background:var(--code);border:1px solid var(--border);border-radius:10px;
    padding:14px 16px;overflow-x:auto}
  pre code{background:none;padding:0;font-size:13px;line-height:1.5}
  .tbl,table{width:100%;border-collapse:collapse;margin:1em 0;font-size:14px;display:block;overflow-x:auto}
  th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}
  th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
  hr{border:none;border-top:1px solid var(--border);margin:1.5em 0}
  footer{color:var(--muted);font-size:12px;padding:24px 0}
  @media (max-width:760px){ .layout{flex-direction:column;gap:0} nav{position:static;height:auto;width:auto;padding:20px 0} main{padding-top:0} }
</style>
</head>
<body>
<div class="layout">
  <nav>
    <div class="brand">Achilles</div>
    <div class="tag">User Guides</div>
    <ul>{{NAV}}</ul>
  </nav>
  <main>
    {{SECTIONS}}
    <footer>Generated from docs/*.md by docs/build.py · LLM-assisted SAST</footer>
  </main>
</div>
</body>
</html>"""

if __name__ == "__main__":
    build()
