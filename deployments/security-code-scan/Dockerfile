# Achilles — Security Code Scan (.NET C#/VB SAST, LGPL-3.0). Emits SARIF 2.1.
# Invoked as a separate process, so LGPL is commercial-safe. Bundles the
# `security-scan` dotnet global tool on the .NET SDK.
#
# Build:
#   docker build -t achilles/security-code-scan:5.6.7 deployments/security-code-scan
#
# Heaviest integration by requirements — security-scan loads the .sln/.csproj via
# MSBuildWorkspace, which:
#   * needs the .NET SDK,
#   * restores NuGet packages  -> needs network egress (so this tool sets
#     network: default in configs/tools.yaml; incompatible with strict-containment),
#   * writes obj/              -> so the wrapper copies the read-only source to a
#     writable workdir before restoring/scanning,
#   * needs a real .NET project as the target (not a bare directory) -> the wrapper
#     discovers the .sln/.csproj.
FROM mcr.microsoft.com/dotnet/sdk:8.0@sha256:ec9c0a0dc5f60adc2065762050638dd5ed5facfc53716d4580a42d86027c8e80
# Pinned by digest so a rebuild gets the same base; Dependabot proposes updates.

ARG SCS_VERSION=5.6.7
RUN dotnet tool install --global security-scan --version ${SCS_VERSION}
ENV PATH="${PATH}:/root/.dotnet/tools"
# security-scan 5.6.7 targets .NET 6; the SDK 8.0 image ships only the 8.0
# runtime, so roll the framework-dependent app forward onto it.
ENV DOTNET_ROLL_FORWARD=LatestMajor

COPY scan.sh /usr/local/bin/scan.sh
RUN chmod +x /usr/local/bin/scan.sh

# scan.sh <src-root> [security-scan flags...]
ENTRYPOINT ["/usr/local/bin/scan.sh"]
