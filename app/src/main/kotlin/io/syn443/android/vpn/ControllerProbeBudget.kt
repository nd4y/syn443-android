package io.syn443.android.vpn

import io.syn443.decision.AdaptiveProbeBudget

/** RAM ownership for the process containing TunnelService. Native/service
 * recreation cannot replenish adaptive start admission. This is not durable
 * across controller-process death and does not gate other probe subsystems. */
internal object ControllerProbeBudget {
    val adaptive=AdaptiveProbeBudget()
}
