package io.syn443.android.vpn

import io.syn443.decision.Context
import io.syn443.decision.FailoverAdmission
import io.syn443.decision.FailoverAlgorithm
import io.syn443.decision.FailoverChoice
import io.syn443.decision.VerifiedPathSample
import org.json.JSONObject

/** Both policies see the observed path until their first different proposal. */
internal class FailoverShadow(
    private val context: Context,
    private val reference: FailoverAdmission,
) {
    private var comparedThrough = 0L
    private var batches = 0L
    private var difference: String? = null

    fun observe(
        sequence: Long, receipt: String, now: Long, selected: String,
        active: VerifiedPathSample, reserves: List<VerifiedPathSample>, live: FailoverChoice?,
    ) {
        if (difference != null || sequence <= comparedThrough) return
        val other = reference.decide(context, sequence, receipt, now, selected, active, reserves)
        if (!reference.consumed(sequence)) return
        comparedThrough = sequence
        batches++
        difference = when {
            live?.candidate == other?.candidate -> null
            live == null -> "reference_only"
            other == null -> "live_only"
            else -> "different_reserve"
        }
    }

    fun status():JSONObject? = if (batches==0L) null else JSONObject()
        .put("liveRevision", FailoverAlgorithm.CONFIRMED.revision)
        .put("referenceRevision", FailoverAlgorithm.BASELINE.revision)
        .put("comparedBatches", batches)
        .put("outcome", difference ?: "agree")
}
