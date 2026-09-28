/* c_dispatch/src/dispatcher.c
 * Phase 4: The Adaptive Router
 *
 * Intercepts the handshake immediately before the cryptographic
 * execution phase.  The routing decision is a pure function of
 * the global HostProfile and the cipher suite descriptor:
 *
 *   ┌──────────────────────────────────────────────────────────────┐
 *   │ Rule 1: VM + ≤2 cores               → ROUTE_SEQUENTIAL     │
 *   │ Rule 2: X25519 + ML-KEM-768 (light) → ROUTE_SEQUENTIAL     │
 *   │ Rule 3: Non-hybrid profile           → ROUTE_SEQUENTIAL     │
 *   │ Rule 4: Bare-metal + P-384 + ML-KEM-1024 (heavy)           │
 *   │         + >2 cores                   → ROUTE_PARALLEL       │
 *   │ Rule 5: ≥3 cores + any hybrid       → ROUTE_PARALLEL       │
 *   │ Default:                             → ROUTE_SEQUENTIAL     │
 *   └──────────────────────────────────────────────────────────────┘
 */

#include "../include/dispatcher.h"
#include "../include/telemetry.h"
#include "../include/algo_config.h"

/* ═══════════════════════════════════════════════════════════════════
 * Routing Decision
 * ═══════════════════════════════════════════════════════════════════ */

DispatchRoute adaptive_dispatch(const AlgoCombo *combo)
{
    const HostProfile *hp = get_host_profile();

    /* Rule 1: Virtualised environment with ≤2 cores
     * Scheduler overhead dominates on small VMs — sequential is safer. */
    if (hp->is_virtualized && hp->logical_cores <= 2)
        return ROUTE_SEQUENTIAL;

    /* Rule 2: Lightweight cipher suite (X25519 + ML-KEM-768)
     * Both primitives are fast enough that the pthread_cond_signal
     * overhead exceeds the parallelism benefit. */
    if (combo->classical_curve == CURVE_X25519 &&
        combo->pqc_alg == PQC_MLKEM_768)
        return ROUTE_SEQUENTIAL;

    /* Rule 3: Non-hybrid profiles have no parallelism benefit
     * (only one crypto family is active). */
    if (combo->pqc_alg == PQC_NONE ||
        combo->classical_curve == CURVE_NONE)
        return ROUTE_SEQUENTIAL;

    /* Rule 4: Heavy cipher on bare-metal with dedicated cores
     * P-384 ECDH is expensive (~0.5 ms) and ML-KEM-1024 encaps/decaps
     * is heavy enough to amortise the dispatch overhead. */
    if (!hp->is_virtualized && hp->logical_cores > 2 &&
        combo->classical_curve == CURVE_P384 &&
        combo->pqc_alg == PQC_MLKEM_1024)
        return ROUTE_PARALLEL;

    /* Rule 5: Sufficient physical cores + medium-weight hybrid
     * (e.g. P-256 + ML-KEM-768, P-256 + ML-KEM-1024) */
    if (hp->logical_cores > 2 && combo->profile == PROFILE_HYBRID)
        return ROUTE_PARALLEL;

    /* Default: sequential is the conservative, safe choice. */
    return ROUTE_SEQUENTIAL;
}

/* ═══════════════════════════════════════════════════════════════════
 * Combined dispatch + execute
 * ═══════════════════════════════════════════════════════════════════ */

int dispatch_execute(const AlgoCombo *combo, HandshakeRole role,
                     SharedCryptoResult *result)
{
    DispatchRoute route = adaptive_dispatch(combo);

    if (route == ROUTE_PARALLEL)
        return execute_parallel_optimized(combo, role, result);
    else
        return execute_sequential(combo, role, result);
}

/* ═══════════════════════════════════════════════════════════════════
 * Utility
 * ═══════════════════════════════════════════════════════════════════ */

const char *route_name(DispatchRoute route)
{
    switch (route) {
        case ROUTE_SEQUENTIAL: return "Sequential";
        case ROUTE_PARALLEL:   return "Parallel";
        default:               return "Unknown";
    }
}
