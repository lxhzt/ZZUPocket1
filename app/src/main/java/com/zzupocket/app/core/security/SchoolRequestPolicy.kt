package com.zzupocket.app.core.security

import java.util.Base64
import okhttp3.Request

/** Client-side containment only: this does not change the school's token permissions. */
enum class SchoolService { CAS, EAS, GMS, FINANCE_DISABLED }

object SchoolRequestPolicy {
    private const val MICRO = "/eams-micro-server/api/v1"
    private val easGetPaths = setOf(
        "/eams-door/api/v1/calendar/get-all-semesters",
        "/eams-door/api/v1/portal/home/user-info",
        "$MICRO/semester/current-semester", "$MICRO/room/system/course-units",
        "$MICRO/room/place/campus", "$MICRO/room/place/roomTypes", "$MICRO/room/place/floors",
    )
    private val casQueries = mapOf(
        "/token/jwt/publicKey" to emptySet(),
        "/token/mfa/detect" to setOf("username", "password", "deviceId"),
        "/token/mfa/initByType/securephone" to setOf("state"),
        "/token/password/passwordLogin" to setOf("username", "password", "appId", "osType", "geo", "deviceId", "clientId", "mfaState"),
    )
    private val guid = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    private val gmsRoute = Regex("MyHeartWillGoOn(pygl/xskbcx/(kbcx_drop|loadKb|bzkb_load))#$guid")

    fun permits(request: Request, service: SchoolService): Boolean {
        val url = request.url
        if (!SchoolNetworkPolicy.permits(url) || url.fragment != null || '%' in url.encodedPath) return false
        if (request.header("Host") != null || request.header("Proxy-Authorization") != null ||
            request.header("X-Id-Token") != null) return false
        return when (service) {
            SchoolService.FINANCE_DISABLED -> false
            SchoolService.CAS -> {
                if (url.host != "cas.s.zzu.edu.cn" || request.header("Authorization") != null ||
                    request.header("Cookie") != null) return false
                val path = url.encodedPath
                val allowed = casQueries[path]
                if (allowed != null) {
                    val method = if (path == "/token/jwt/publicKey" || path == "/token/mfa/initByType/securephone") "GET" else "POST"
                    request.method == method && queriesAllowed(request, allowed)
                } else {
                    // The existing CAS protocol supports returned attest bases and its legacy fallback.
                    request.method == "POST" && url.query == null && Regex(
                        "/(?:attest/)?(?:api/guard/){1,2}securephone/(send|valid)"
                    ).matches(path)
                }
            }
            SchoolService.EAS -> {
                if (url.host != "jwxt.zzu.edu.cn" || request.header("Authorization").isNullOrBlank() ||
                    request.header("Cookie") != null) return false
                val path = url.encodedPath
                when {
                    path in easGetPaths -> request.method == "GET" && url.query == null
                    path == "$MICRO/room/place/building" -> request.method == "GET" && queriesAllowed(request, setOf("campusAssoc"))
                    Regex("$MICRO/lesson/student/course-table/[0-9]+").matches(path) -> request.method == "GET" && url.query == null
                    path == "$MICRO/room/place/rooms" -> request.method == "POST" && url.query == null
                    else -> false
                }
            }
            SchoolService.GMS -> {
                if (url.host != "gmsstu.zzu.edu.cn" || url.query != null ||
                    request.header("Authorization") != null) return false
                if (url.encodedPath == "/stu/") return request.method == "GET"
                val encoded = url.encodedPath.removePrefix("/stu/")
                if (encoded.length > 256 || !url.encodedPath.startsWith("/stu/")) return false
                val plain = runCatching {
                    val bytes = Base64.getDecoder().decode(encoded.replace('_', '='))
                    if (Base64.getEncoder().encodeToString(bytes).replace('=', '_') != encoded) return false
                    String(bytes, Charsets.US_ASCII)
                }.getOrNull() ?: return false
                val route = gmsRoute.matchEntire(plain) ?: return false
                request.method == if (route.groupValues[2] == "kbcx_drop") "GET" else "POST"
            }
        }
    }

    private fun queriesAllowed(request: Request, names: Set<String>): Boolean =
        request.url.queryParameterNames.all { it in names && request.url.queryParameterValues(it).size == 1 }
}
