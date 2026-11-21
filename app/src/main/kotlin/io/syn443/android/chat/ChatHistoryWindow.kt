package io.syn443.android.chat

import org.json.JSONObject

internal data class ChatInboxWindow(
    val rows: List<JSONObject> = emptyList(),
    val olderAvailable: Boolean = false,
    val historical: Boolean = false,
) {
    fun request(older: Boolean): Pair<Long, String>? {
        if (!older) return 0L to ""
        if (!olderAvailable) return null
        return rows.last().let { it.getLong("updatedAt") to it.getString("id") }
    }

    fun accept(page: List<JSONObject>, older: Boolean): ChatInboxWindow {
        val (before, id) = request(older) ?: return this
        require(page.size <= 50)
        if (older && page.isEmpty()) return copy(olderAvailable = false)
        var cursorTime = before
        var cursorId = id
        for (row in page) {
            val time = row.getLong("updatedAt")
            val nextId = row.getString("id")
            require(time > 0 && nextId.isNotEmpty() && (cursorTime == 0L || time < cursorTime || time == cursorTime && nextId < cursorId))
            cursorTime = time
            cursorId = nextId
        }
        return ChatInboxWindow(page.toList(), page.size == 50, historical = older)
    }
}

internal enum class HistoryMove { LATEST, POLL, OLDER, NEWER }

internal data class ChatMessageWindow(
    val rows: List<JSONObject> = emptyList(),
    val olderAvailable: Boolean = false,
    val historical: Boolean = false,
    private val newestSeen: Long = 0L,
) {
    val newerAvailable: Boolean get() = historical

    fun request(move: HistoryMove): Pair<Long, Long>? = when (move) {
        HistoryMove.LATEST -> 0L to 0L
        HistoryMove.POLL -> if (historical) null else 0L to (rows.lastOrNull()?.getLong("sequence") ?: 0L)
        HistoryMove.OLDER -> if (olderAvailable) rows.first().getLong("sequence") to 0L else null
        HistoryMove.NEWER -> if (newerAvailable) 0L to rows.last().getLong("sequence") else null
    }

    fun accept(move: HistoryMove, page: List<JSONObject>): ChatMessageWindow {
        val (before, after) = request(move) ?: return this
        require(page.size <= 20)
        val sorted = page.sortedBy { it.getLong("sequence") }
        val sequences = sorted.map { it.getLong("sequence") }
        require(sequences.distinct().size == sequences.size && sequences.all { it > after && (before == 0L || it < before) })
        if (sorted.isEmpty()) return when (move) {
            HistoryMove.LATEST -> ChatMessageWindow()
            HistoryMove.POLL -> this
            HistoryMove.OLDER -> copy(olderAvailable = false)
            HistoryMove.NEWER -> copy(historical = false)
        }
        val nextRows = if (move == HistoryMove.POLL) (rows + sorted).takeLast(20) else sorted
        val oldest = nextRows.first().getLong("sequence")
        val newest = nextRows.last().getLong("sequence")
        val browsing = move == HistoryMove.OLDER || move == HistoryMove.NEWER && newest < newestSeen && page.size == 20
        return ChatMessageWindow(nextRows, olderAvailable = oldest > 1 &&
            (move != HistoryMove.OLDER || sorted.size == 20), historical = browsing,
            newestSeen = maxOf(newest, newestSeen))
    }
}

internal suspend fun loadChatMessagePage(
    conversation: String,
    previous: ChatMessageWindow,
    move: HistoryMove,
    fetch: suspend (JSONObject) -> JSONObject,
    current: () -> Boolean,
    visible: () -> Boolean,
    publish: (ChatMessageWindow, Long) -> Unit,
    acknowledge: suspend (JSONObject) -> Unit,
) {
    val (before, after) = previous.request(move) ?: return
    val page = fetch(JSONObject().put("conversation", conversation).put("before", before).put("after", after))
    if (!current()) return
    val messages = page.getJSONArray("messages")
    require(messages.length() <= 20)
    val rows = List(messages.length()) { index -> messages.getJSONObject(index) }
    require(rows.all { it.getString("conversation") == conversation })
    val next = previous.accept(move, rows)
    publish(next, page.getLong("peerRead"))
    if (visible() && !next.historical && move != HistoryMove.OLDER && next.rows.isNotEmpty()) {
        acknowledge(JSONObject().put("conversation", conversation).put("sequence", next.rows.last().getLong("sequence")))
    }
}
