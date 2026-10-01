# Achilles — Psalm (PHP static analysis with security taint tracking, MIT).
# Emits SARIF. Invoked as a separate process; MIT is fully commercial-safe.
# No official Psalm container exists, so we build one from the pinned psalm.phar.
#
# Build:
#   docker build -t achilles/psalm:6.16.1 deployments/psalm
#
# IMPORTANT — needs a project psalm.xml: Psalm requires a config file, and its
# <projectFiles> resolve relative to that config. Achilles points --config at the
# target's own psalm.xml (most Psalm-using PHP projects have one). Run
# `composer install` in the target first so Psalm can resolve types/autoload.
FROM php:8.3-cli
# TODO: pin the base image by digest before release.

# Psalm needs ext-mbstring (not built into the base image) + curl/unzip to fetch.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libonig-dev curl unzip ca-certificates \
 && docker-php-ext-install mbstring >/dev/null \
 && rm -rf /var/lib/apt/lists/*

ARG PSALM_VERSION=6.16.1
ARG PSALM_SHA256=7ace71e4f698466e7e16810679a1895ea623060579aff46fcf9fd0f1c09abe00

RUN curl -fsSL -o /usr/local/bin/psalm.phar \
      "https://github.com/vimeo/psalm/releases/download/${PSALM_VERSION}/psalm.phar" \
 && echo "${PSALM_SHA256}  /usr/local/bin/psalm.phar" | sha256sum -c - \
 && chmod +x /usr/local/bin/psalm.phar

# Callers pass Psalm flags, e.g.:
#   --config=/mnt/src/psalm.xml --root=/mnt/src --taint-analysis --report=/mnt/out/results.sarif
ENTRYPOINT ["php", "/usr/local/bin/psalm.phar"]
