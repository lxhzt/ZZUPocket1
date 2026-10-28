package com.zzupocket.app.securitylab

/** Identity captured from the actual lab dialog's root LayoutParams, not inferred from other windows. */
data class WindowDumpIdentity(val title: String, val type: Int, val ownerPackage: String, val ownerUid: Int)

/** Parse named overlay protection only within the matched window's own attribute record. */
object WindowDumpEvidence {
    private const val APPLICATION = 2
    private val headers = Regex("""(?m)^[ \t]*Window #\d+ Window\{([^\r\n]*)\}:[ \t]*$""")
    private val headerTitle = Regex("""^\S+[ \t]+u\d+[ \t]+(.+)$""")
    private val owners = Regex("""(?m)^[ \t]+mOwnerUid=(\d+)[^\r\n]*$""")
    private val packages = Regex("""(?:^|[ \t])package=([^ \t\r\n]+)(?=[ \t]|$)""")
    private val attributeStart = Regex("""(?m)^[ \t]+mAttrs=\{""")
    private val types = Regex("""(?:^|[ \t\r\n])ty=([A-Z_]+|\d+)(?=[ \t\r\n}]|$)""")
    private val privateFlags = Regex("""(?:^|[ \t\r\n])pfl=([^\r\n}]*)""")
    private val overlayNames = setOf(
        "HIDE_NON_SYSTEM_OVERLAY_WINDOWS",
        "PRIVATE_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS",
        "SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS",
    )

    fun confirmsHiddenOverlays(dump: String, expected: WindowDumpIdentity): Boolean {
        if (expected.type != APPLICATION || expected.ownerUid < 0 ||
            expected.title.isBlank() || expected.title.any { it == '\r' || it == '\n' || it == '{' || it == '}' }) return false
        val windows = headers.findAll(dump).toList()
        val matching = windows.withIndex().filter { (_, header) ->
            headerTitle.matchEntire(header.groupValues[1])?.groupValues?.get(1) == expected.title
        }
        // A unique local title is required. Ambiguous or unrecognized output is not positive evidence.
        if (matching.size != 1) return false
        val (index, header) = matching.single()
        val end = windows.getOrNull(index + 1)?.range?.first ?: dump.length
        val body = dump.substring(header.range.last + 1, end)
        val owner = owners.findAll(body).toList().singleOrNull() ?: return false
        val start = attributeStart.findAll(body).toList().singleOrNull() ?: return false
        if (owner.range.first >= start.range.first || owner.groupValues[1].toIntOrNull() != expected.ownerUid) return false
        if (packages.findAll(owner.value).toList().singleOrNull()?.groupValues?.get(1) != expected.ownerPackage) return false
        val attributes = balancedRecord(body, start.range.last) ?: return false
        val type = types.findAll(attributes).toList().singleOrNull()?.groupValues?.get(1) ?: return false
        if (type != "APPLICATION" && type != APPLICATION.toString()) return false
        val flags = privateFlags.findAll(attributes).toList().singleOrNull()?.groupValues?.get(1) ?: return false
        // Do not accept a flag from another field, another window or the global dump footer.
        return flags.split(Regex("""[ \t|]+""")).any { it in overlayNames }
    }

    private fun balancedRecord(text: String, opening: Int): String? {
        var depth = 0
        for (index in opening until text.length) {
            when (text[index]) {
                '{' -> depth++
                '}' -> {
                    depth--
                    if (depth == 0) return text.substring(opening + 1, index)
                    if (depth < 0) return null
                }
            }
        }
        return null
    }
}
