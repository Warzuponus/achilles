# Railroader (Ruby on Rails SAST)

[Railroader](https://railroader.org/) is the **MIT-licensed fork of Brakeman**,
created so a Brakeman-class Rails scanner can be used commercially. **License:
MIT** — fully commercial-safe, invoked as a separate-process container.

## Why Railroader (not Brakeman)

Brakeman is **CC-BY-NC-SA** (non-commercial) — it's blocked in commercial mode
(see the `brakeman` entry in `configs/tools.yaml`). Railroader is the drop-in MIT
fork; it shares Brakeman's checks and its JSON output schema.

## Why a custom image + JSON (not SARIF)

- No official container image exists, so we build a pinned one here.
- Railroader has no SARIF formatter, so Achilles runs `-f json` and normalizes
  the native JSON with `internal/normalize/railroader.go` (`format: railroader`).

## Scope

Railroader analyzes **Rails applications** (it expects the app structure —
`config/`, `app/`, a `Gemfile`), not arbitrary Ruby files. It's static analysis:
no `bundle install` or app boot required.

## Dependency pinning

Railroader 4.3.8 is unmaintained and pins the ancient `ruby_parser ~> 3.13.1` /
`sexp_processor ~> 4.9`. On a modern Ruby, `gem install railroader` pulls a newer
`sexp_processor` that's incompatible with that `ruby_parser` and crashes
(`SexpTypeError`). The image therefore pins the whole known-good trio
(`sexp_processor 4.17.4`, `ruby_parser 3.13.1`, `railroader 4.3.8`) on
`ruby:2.7-slim`, the Ruby era it targets.

## Build

```bash
docker build -t achilles/railroader:4.3.8 deployments/railroader
```

Verified end-to-end in the `tier2-verify` CI workflow against a minimal Rails app
with a SQL-injection and a command-injection sink.
