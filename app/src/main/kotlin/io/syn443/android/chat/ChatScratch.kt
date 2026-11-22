package io.syn443.android.chat

import java.io.File

/** The chat Activity, compressor and exporter run in the main application process. */
internal object ChatScratch {
    private val session = ChatLimits.id()
    private const val ID = "[0-9a-f]{32}"
    private val scratchName = Regex("""chat-(?:download-(?:$ID-)?$ID|(?:$ID-)?$ID\.(?:input|output))""")

    fun input(directory: File) = File(directory, "chat-$session-${ChatLimits.id()}.input")
    fun output(directory: File) = File(directory, "chat-$session-${ChatLimits.id()}.output")
    fun download(directory: File) = File(directory, "chat-download-$session-${ChatLimits.id()}")

    fun removeAbandoned(directory: File) {
        val mediaPrefix = "chat-$session-"
        val downloadPrefix = "chat-download-$session-"
        directory.listFiles()?.asSequence()?.filter { file ->
            val name = file.name
            !name.startsWith(mediaPrefix) && !name.startsWith(downloadPrefix) &&
                scratchName.matches(name) && file.isFile
        }?.take(256)?.forEach { it.delete() }
    }
}
