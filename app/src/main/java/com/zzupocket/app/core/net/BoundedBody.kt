package com.zzupocket.app.core.net

import java.io.IOException
import okhttp3.ResponseBody

/** Bound decompressed responses too; Content-Length alone is not a resource limit. */
fun ResponseBody?.readBoundedText(maxBytes: Long = 4L * 1024 * 1024): String {
    if (this == null) return ""
    use {
        if (contentLength() > maxBytes) throw IOException("响应超过安全大小限制")
        val source = source()
        source.request(maxBytes + 1)
        if (source.buffer.size > maxBytes) throw IOException("响应超过安全大小限制")
        val text = source.readString(contentType()?.charset(Charsets.UTF_8) ?: Charsets.UTF_8)
        checkJsonDepth(text)
        return text
    }
}

private fun checkJsonDepth(text: String) {
    if (text.firstOrNull { !it.isWhitespace() } !in listOf('{', '[')) return
    var depth = 0
    var quoted = false
    var escaped = false
    for (char in text) {
        if (quoted) {
            if (escaped) escaped = false
            else if (char == '\\') escaped = true
            else if (char == '"') quoted = false
        } else when (char) {
            '"' -> quoted = true
            '{', '[' -> { depth++; if (depth > 64) throw IOException("JSON 嵌套超过安全限制") }
            '}', ']' -> depth--
        }
    }
}
