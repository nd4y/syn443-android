package io.syn443.decision

/** Wire preflight preserves duplicate keys before serialization can discard them. */
internal class StrictJson private constructor(private val text: String) {
    private var index = 0

    private fun whitespace() {
        while (index < text.length && text[index] in " \n\r\t") index++
    }

    private fun take(c: Char) {
        whitespace()
        require(index < text.length && text[index++] == c)
    }

    private fun peek(): Char {
        whitespace()
        require(index < text.length)
        return text[index]
    }

    private fun string(): String {
        whitespace()
        val start = index
        take('"')
        while (index < text.length) {
            val c = text[index++]
            require(c >= ' ')
            if (c == '"') return Decision.json.decodeFromString<String>(text.substring(start, index))
            if (c == '\\') {
                require(index < text.length)
                index++
            }
        }
        error("Unterminated JSON string")
    }

    private fun value(depth: Int) {
        require(depth <= 16)
        when (peek()) {
            '{' -> {
                take('{')
                val keys = HashSet<String>()
                if (peek() != '}') {
                    while (true) {
                        require(keys.size < 64 && keys.add(string()))
                        take(':')
                        value(depth + 1)
                        if (peek() == '}') break
                        take(',')
                    }
                }
                take('}')
            }
            '[' -> {
                take('[')
                var size = 0
                if (peek() != ']') {
                    while (true) {
                        require(++size <= 4096)
                        value(depth + 1)
                        if (peek() == ']') break
                        take(',')
                    }
                }
                take(']')
            }
            '"' -> string()
            't' -> literal("true")
            'f' -> literal("false")
            'n' -> literal("null")
            in '0'..'9' -> {
                if (text[index] == '0') index++ else {
                    while (index < text.length && text[index] in '0'..'9') index++
                }
            }
            else -> error("Expected nonnegative integer or JSON value")
        }
    }

    private fun literal(expected: String) {
        require(text.startsWith(expected, index))
        index += expected.length
    }

    companion object {
        fun validate(raw: String) {
            require(raw.length <= (1 shl 20))
            require(raw.toByteArray(Charsets.UTF_8).size <= (1 shl 20))
            val parser = StrictJson(raw)
            parser.value(0)
            parser.whitespace()
            require(parser.index == raw.length)
        }
    }
}

