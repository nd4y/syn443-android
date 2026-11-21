package io.syn443.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import io.syn443.android.chat.ChatHistoryNavigation
import io.syn443.android.chat.ChatInboxWindow
import io.syn443.android.chat.ChatMessageWindow
import io.syn443.android.chat.HistoryMove
import io.syn443.android.chat.loadChatMessagePage
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

class ChatHistoryWindowTest {
    @get:Rule val compose = createComposeRule()

    private fun fixtureId(number: Int) = number.toString(16).padStart(32, '0')

    @Test fun equalTimestampInboxPagesReachEveryConversationAndReturnToFirst() {
        val all = (253 downTo 1).map { JSONObject().put("id", fixtureId(it)).put("updatedAt", 100L) }
        var window = ChatInboxWindow()
        val seen = mutableListOf<String>()
        fun fetch(older: Boolean) {
            val (time, id) = requireNotNull(window.request(older))
            val page = all.filter { time == 0L || it.getString("id") < id }.take(50)
            window = window.accept(page, older)
        }
        fetch(false)
        for (index in 0..5) {
            assertTrue(window.rows.size <= 50)
            seen.addAll(window.rows.map { it.getString("id") })
            if (!window.olderAvailable) break
            fetch(true)
            assertTrue(window.historical)
        }
        assertEquals(all.map { it.getString("id") }, seen)
        assertNull(window.request(true))
        fetch(false)
        assertFalse(window.historical)
        assertEquals(all.take(50), window.rows)
        val end = window.accept(emptyList(), older = true)
        assertEquals(window.rows, end.rows)
        assertFalse(end.olderAvailable)
        assertTrue(runCatching { window.accept(all.take(50), older = true) }.isFailure)
    }

    @Test fun deepMessagesNavigateBothDirectionsWithoutPollingOrSkippingHistory() {
        var last = 253
        var window = ChatMessageWindow()
        fun fetch(move: HistoryMove) {
            val (before, after) = requireNotNull(window.request(move))
            val numbers = if (after > 0L) (after.toInt()+1..last).take(20)
                else (minOf(last, if (before == 0L) last else before.toInt()-1) downTo 1).take(20)
            window = window.accept(move, numbers.map { JSONObject().put("id", fixtureId(it)).put("sequence", it) })
            assertTrue(window.rows.size <= 20)
        }
        fun displayed() = window.rows.map { it.getInt("sequence") }
        fetch(HistoryMove.LATEST)
        assertEquals((234..253).toList(), displayed())
        val seen = displayed().toMutableSet()
        for (index in 0..12) {
            if (!window.olderAvailable) break
            fetch(HistoryMove.OLDER)
            assertTrue(window.historical)
            assertNull(window.request(HistoryMove.POLL))
            displayed().forEach { assertTrue(seen.add(it)) }
        }
        assertEquals((1..253).toSet(), seen)
        assertEquals((1..13).toList(), displayed())
        last = 257
        for (index in 0..12) {
            if (!window.newerAvailable) break
            fetch(HistoryMove.NEWER)
        }
        assertFalse(window.historical)
        fetch(HistoryMove.POLL)
        assertEquals((238..257).toList(), displayed())
        fetch(HistoryMove.OLDER)
        val archived = displayed()
        window = window.accept(HistoryMove.OLDER, emptyList())
        assertFalse(window.olderAvailable)
        assertTrue(window.historical)
        assertEquals(archived, displayed())
        fetch(HistoryMove.LATEST)
        assertFalse(window.historical)
        assertEquals((238..257).toList(), displayed())
    }

    @Test fun archiveButtonsReturnToLatestOrMoveOnePageAndRespectBusyState() {
        val moves = mutableListOf<HistoryMove>()
        val enabled = mutableStateOf(false)
        compose.setContent { MaterialTheme { ChatHistoryNavigation(enabled.value) { moves.add(it) } } }
        val next = compose.onNodeWithText("Следующие сообщения")
        val latest = compose.onNodeWithText("К последним сообщениям")
        next.assertIsNotEnabled()
        latest.assertIsNotEnabled()
        compose.runOnIdle { enabled.value = true }
        next.performClick()
        latest.performClick()
        compose.runOnIdle { assertEquals(listOf(HistoryMove.NEWER, HistoryMove.LATEST), moves) }
    }

    @Test fun lateForeignOrHiddenPagesCannotAcknowledgeTheActiveConversation() = runBlocking {
        val id = fixtureId(1)
        var window = ChatMessageWindow()
        val receipts = mutableListOf<Long>()
        var requests = 0
        var showing = true
        val fetch = { query: JSONObject ->
            requests++
            assertEquals(id, query.getString("conversation"))
            val seq = if (query.getLong("before") > 0L) 41L else 42L
            JSONObject().put("peerRead", 7L).put("messages", JSONArray().put(
                JSONObject().put("conversation", id).put("sequence", seq)))
        }
        suspend fun load(move: HistoryMove, current: Boolean = true, foreign: Boolean = false) {
            loadChatMessagePage(id, window, move, fetch = { query ->
                fetch(query).also { if (foreign) it.getJSONArray("messages").getJSONObject(0).put("conversation", fixtureId(2)) }
            }, current = { current }, visible = { showing }, publish = { next, peer ->
                assertEquals(7L, peer)
                window = next
            }, acknowledge = { receipts.add(it.getLong("sequence")) })
        }
        load(HistoryMove.LATEST, current = false)
        assertTrue(window.rows.isEmpty())
        assertTrue(runCatching { load(HistoryMove.LATEST, foreign = true) }.isFailure)
        assertTrue(window.rows.isEmpty())
        showing = false
        load(HistoryMove.LATEST)
        assertTrue(receipts.isEmpty())
        showing = true
        load(HistoryMove.LATEST)
        assertEquals(listOf(42L), receipts)
        load(HistoryMove.OLDER)
        assertTrue(window.historical)
        val before = requests
        load(HistoryMove.POLL)
        assertEquals(before, requests)
        assertEquals(listOf(42L), receipts)
    }
}
