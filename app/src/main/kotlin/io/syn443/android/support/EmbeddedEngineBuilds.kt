package io.syn443.android.support

import android.content.res.AssetManager
import org.json.JSONObject

/** Packaged public source revisions. Reading them never starts a native engine. */
class EmbeddedEngineBuilds private constructor(val singBoxRevision: String, val netBirdRevision: String) {
    fun json(): JSONObject = JSONObject().put("schemaVersion", 1)
        .put("singBoxRevision", singBoxRevision).put("netBirdRevision", netBirdRevision)

    companion object {
        private val revision = Regex("[a-f0-9]{40}")
        private val fields = setOf("schemaVersion", "singBoxRevision", "netBirdRevision")

        fun read(assets: AssetManager): EmbeddedEngineBuilds? = runCatching {
            val bytes = ByteArray(257)
            var size = 0
            assets.open("engine-builds.json").use { input ->
                while (size < bytes.size) {
                    val count = input.read(bytes, size, bytes.size - size)
                    if (count == -1) break
                    require(count > 0)
                    size += count
                }
            }
            require(size in 1..256)
            val value = JSONObject(String(bytes, 0, size, Charsets.UTF_8))
            require(value.keys().asSequence().toSet() == fields && value.opt("schemaVersion") == 1)
            val singBox = value.opt("singBoxRevision") as? String ?: return null
            val netBird = value.opt("netBirdRevision") as? String ?: return null
            require(revision.matches(singBox) && revision.matches(netBird))
            EmbeddedEngineBuilds(singBox, netBird)
        }.getOrNull()
    }
}
