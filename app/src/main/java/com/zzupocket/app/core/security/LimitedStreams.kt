package com.zzupocket.app.core.security

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

fun InputStream.copyLimitedTo(output: OutputStream, maxBytes: Long = 32L * 1024 * 1024) {
    val buffer = ByteArray(64 * 1024)
    var total = 0L
    while (true) {
        val read = read(buffer)
        if (read == -1) return
        if (read == 0) continue
        total += read
        if (total > maxBytes) throw IOException("图片超过安全大小限制")
        output.write(buffer, 0, read)
    }
}

/** Bound both dimensions, including narrow/tall decompression bombs. */
fun imageSampleSize(width: Int, height: Int, maxEdge: Int = 2048): Int {
    require(width > 0 && height > 0 && maxEdge > 0)
    val edge = maxOf(width, height).toLong()
    return ((edge + maxEdge - 1) / maxEdge).coerceAtLeast(1).toInt()
}
