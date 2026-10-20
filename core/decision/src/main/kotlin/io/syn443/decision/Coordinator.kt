package io.syn443.decision

data class Snapshot(val context: Context, val desiredOn: Boolean, val activePathId: String?)

class Coordinator(initial: Context) {
    private var state = Snapshot(initial, false, null)

    init { require(Decision.validContext(initial)) }

    @Synchronized fun snapshot(): Snapshot = state

    @Synchronized private fun intent(on: Boolean): Context {
        if (!on && state.context.activationGeneration == Decision.MAX_GENERATION) {
            state = Snapshot(state.context, false, null)
            return state.context
        }
        check(state.context.activationGeneration < Decision.MAX_GENERATION)
        val next = state.context.copy(activationGeneration = state.context.activationGeneration + 1)
        state = Snapshot(next, on, null)
        return next
    }

    fun start(): Context = intent(true)
    fun stop(): Context = intent(false)

    @Synchronized fun networkChanged(): Context {
        check(state.context.networkEpoch < Decision.MAX_GENERATION)
        val next = state.context.copy(networkEpoch = state.context.networkEpoch + 1)
        state = state.copy(context = next, activePathId = null)
        return next
    }

    @Synchronized fun engineChanged(): Context {
        check(state.context.engineGeneration < Decision.MAX_GENERATION)
        val next = state.context.copy(engineGeneration = state.context.engineGeneration + 1)
        state = state.copy(context = next, activePathId = null)
        return next
    }

    @Synchronized fun activate(config: String, algorithm: String, hash: String): Context {
        check(state.context.activationGeneration < Decision.MAX_GENERATION)
        val next = state.context.copy(
            activationGeneration = state.context.activationGeneration + 1,
            configRevision = config,
            algorithmRevision = algorithm,
            dependencyHash = hash,
        )
        require(Decision.validContext(next))
        state = state.copy(context = next, activePathId = null)
        return next
    }

    @Synchronized fun tryApply(token: Context, pathId: String): Boolean {
        if (!state.desiredOn || token != state.context || !Decision.validId(pathId)) return false
        state = state.copy(activePathId = pathId)
        return true
    }
}

