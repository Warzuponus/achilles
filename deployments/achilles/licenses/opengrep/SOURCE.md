# Opengrep: source for the binary in this image

The image contains the **unmodified** upstream release binary of Opengrep, a
program licensed under the GNU Lesser General Public License, version 2.1 (the
`LICENSE` file beside this one). Achilles runs it as a separate program and is not
linked with it.

| | |
|---|---|
| Version | v1.25.0 |
| Binary | `opengrep_manylinux_x86` / `opengrep_manylinux_aarch64` from <https://github.com/opengrep/opengrep/releases/tag/v1.25.0>, verified against the sha256 pinned in `deployments/achilles/Dockerfile` |
| Source commit | `27b5fba1b315fbc63d0fd474d01f5d8235cc86e2` |
| Source | <https://github.com/opengrep/opengrep/tree/v1.25.0> (clone with `--recurse-submodules`) |

Keep this file in step with `OPENGREP_VERSION` in the Dockerfile.
