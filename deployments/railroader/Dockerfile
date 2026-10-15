# Achilles — Railroader (Ruby on Rails SAST, MIT). The MIT-licensed fork of
# Brakeman, created specifically so it can be used commercially (Brakeman itself
# is CC-BY-NC-SA and is excluded — see configs/tools.yaml). Fully commercial-safe,
# invoked as a separate-process container.
#
# No official container exists, and Railroader has no SARIF formatter, so we ship
# a pinned gem on a Ruby base and normalize its native JSON
# (internal/normalize/railroader.go, format: railroader).
#
# DEPENDENCY PINNING (important): Railroader 4.3.8 is unmaintained and pins the
# ancient ruby_parser ~> 3.13.1 / sexp_processor ~> 4.9. On a modern Ruby,
# `gem install railroader` pulls a newer sexp_processor that is incompatible with
# that ruby_parser and crashes (SexpTypeError). So we pin the whole known-good
# trio on the Ruby era it targets (validated end-to-end on this set).
#
# Build:
#   docker build -t achilles/railroader:4.3.8 deployments/railroader
FROM ruby:3.2-slim@sha256:84184c9e2c368885a1d0c93ad1953c33d81081058d274b87b4aa6f3e209e5d16
# Pinned by digest so a rebuild gets the same base; Dependabot proposes updates.

# Pin the FULL set of Railroader 4.3.8's direct dependencies to known-good
# versions (captured from a working install). Railroader is unmaintained: on a
# modern Ruby, unpinned deps resolve to latest releases that require Ruby 3.x and
# break the build. Order matters — sexp_processor must be installed FIRST, else
# ruby_parser/ruby2ruby pull a newer sexp_processor (Ruby 3.2+) and the build
# fails. The pinned versions' own upper bounds keep transitive deps on 2.x too.
RUN gem install --no-document 'sexp_processor:4.17.4'
RUN gem install --no-document 'ruby_parser:3.13.1' 'ruby2ruby:2.4.4'
RUN gem install --no-document \
      'erubis:2.7.0' \
      'haml:4.0.7' \
      'highline:1.7.10' \
      'safe_yaml:1.0.5' \
      'sass:3.4.25' \
      'slim:3.0.7' \
      'terminal-table:1.8.0' \
      'railroader:4.3.8'

# Callers pass Railroader flags, e.g.:
#   -f json -o /mnt/out/results.json -q /mnt/src
# Railroader exits non-zero when it finds warnings; Achilles keys success on the
# output file existing, not the exit code.
ENTRYPOINT ["railroader"]
