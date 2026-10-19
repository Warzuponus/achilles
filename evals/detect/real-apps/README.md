# Real-application recall labels

Ground truth for five public, deliberately vulnerable applications, pinned to the
commits below. Unlike `../ground_truth/`, these are not scored by `make eval-detect`:
the runner clones each repository at its pinned commit (a few hundred MB in all), so
it is run on purpose:

```bash
go run ./cmd/achilles-eval --mode detect --ground-truth evals/detect/real-apps \
  --markdown real-apps.md
```

| File | Application | Commit | Labels |
|---|---|---|---|
| `dvwa.json` | [DVWA](https://github.com/digininja/DVWA) (PHP) | `068d974` | 72 |
| `nodegoat.json` | [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) (Node.js) | `c5cb68a` | 26 |
| `pygoat.json` | [PyGoat](https://github.com/adeyosemanputra/pygoat) (Python) | `19d17cc` | 56 |
| `railsgoat.json` | [OWASP RailsGoat](https://github.com/OWASP/railsgoat) (Rails) | `f5951f1` | 32 |
| `webgoat.json` | [OWASP WebGoat](https://github.com/WebGoat/WebGoat) (Java) | `e7b1313` | 84 |

## How the labels were made

- **Selection rule, applied to every app:** every vulnerability that the application's
  own documentation describes (in-app lessons and tutorials, help pages, solution
  write-ups, the RailsGoat wiki and vulnerability specs, code comments that mark a
  spot as vulnerable) and that has a specific location in the source tree. Flaws a
  pattern rule cannot find (access control, CSRF, authentication logic) are included,
  so recall is not flattered. Vulnerable dependency versions, the "impossible" or
  "secure" reference levels, and flaws in vendored minified libraries are left out.
- **Independent of the scanners:** the labels were written from the documentation
  and the code before any scan output was looked at. Each entry's `note` says what
  documentation it rests on. Five RailsGoat labels written from memory of its wiki
  were dropped when the wiki did not confirm them.
- **Lines** bracket the dangerous statement (the query, the unescaped output, the
  missing check) and were checked against the pinned commit. The matcher allows +/-3
  lines.
- **One entry per sink:** a flaw with two separate dangerous statements (DVWA's MySQL
  and SQLite branches, say) has two entries.

Corrections are welcome: a wrong line or a missed documented flaw is a bug in the
benchmark. Re-check every line against the pinned commit before changing it.
