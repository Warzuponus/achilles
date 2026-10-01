# Achilles — SpotBugs + Find Security Bugs (JVM SAST, LGPL-2.1).
#
# Bundles the findsecbugs-cli distribution (SpotBugs 4.9.3 + find-sec-bugs plugin
# 1.14.0 + the findsecbugs.sh launcher). It's invoked as a separate process, so
# LGPL is commercial-safe (same posture as Opengrep). No clean public container
# exists, so Achilles ships this Dockerfile and you build the image.
#
# Build:
#   docker build -t achilles/findsecbugs:1.14.0 deployments/spotbugs-findsecbugs
#
# IMPORTANT — bytecode, not source: SpotBugs analyzes COMPILED .class/.jar files.
# Build the Java/Kotlin/Scala project first (mvn/gradle), then scan the tree that
# contains the build output. Scanning un-built source yields zero findings.
FROM eclipse-temurin:21-jre-jammy
# TODO: pin the base image by digest:
#   docker buildx imagetools inspect --format '{{.Manifest.Digest}}' eclipse-temurin:21-jre-jammy

ARG FSB_VERSION=1.14.0
ARG FSB_SHA256=ff546e16e596ade5b6534a6da87881e569429bf46dfd8faed63ca63cdd69b4f8

RUN apt-get update \
 && apt-get install -y --no-install-recommends unzip curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Download the pinned bundle and verify its checksum before unpacking.
RUN curl -fsSL -o /tmp/fsb.zip \
      "https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-${FSB_VERSION}/findsecbugs-cli-${FSB_VERSION}.zip" \
 && echo "${FSB_SHA256}  /tmp/fsb.zip" | sha256sum -c - \
 && mkdir -p /opt/findsecbugs \
 && unzip -q /tmp/fsb.zip -d /opt/findsecbugs \
 && sed -i 's/\r$//' /opt/findsecbugs/findsecbugs.sh \
 && chmod +x /opt/findsecbugs/findsecbugs.sh \
 && rm /tmp/fsb.zip

# findsecbugs.sh preloads the plugin + include filter and appends "$@", so callers
# pass plain SpotBugs args, e.g.:  -effort:max -sarif=/out/results.sarif /src
# (no -textui: the launcher already selects the text UI on a headless host).
ENTRYPOINT ["/opt/findsecbugs/findsecbugs.sh"]
