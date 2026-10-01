#include <stdlib.h>

/* Known-vulnerable sample for the Tier-2 verification harness.
 * clang-tidy with cert-* checks should report cert-env33-c ("do not call the
 * system() function") — an unconditional finding, no compile database needed. */
void run(const char *cmd)
{
    system(cmd);
}
