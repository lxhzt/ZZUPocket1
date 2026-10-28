package com.zzupocket.app.security

import com.zzupocket.app.core.security.SchoolNetworkInterceptor
import com.zzupocket.app.core.security.SchoolService
import com.zzupocket.app.data.eas.EasClient
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.*
import org.junit.Test

/** A malformed academic response must not select another local import namespace. */
class AcademicNamespaceTest {
    @Test fun `academic responses cannot allocate a graduate cache namespace`() = runBlocking {
        var data = "[{\"id\":-10001},{\"id\":-10002},{\"id\":-2147483648},{\"id\":0},{\"id\":20261}]"
        var calls = 0
        val client = OkHttpClient.Builder()
            .dns(object : Dns {
                override fun lookup(hostname: String): List<java.net.InetAddress> =
                    throw AssertionError("Synthetic test forbids DNS")
            })
            .addInterceptor(SchoolNetworkInterceptor(SchoolService.EAS))
            .addInterceptor {
                calls++
                Response.Builder().request(it.request()).protocol(Protocol.HTTP_1_1)
                    .code(200).message("synthetic").body("{\"result\":0,\"data\":$data}".toResponseBody()).build()
            }.build()
        val api = EasClient(client, Json)
        assertEquals(listOf(0, 20261), api.fetchSemesters("synthetic-token").map { it.id })
        for (id in listOf(-1, -10001, -10002, Int.MIN_VALUE)) {
            data = "{\"id\":$id}"
            assertNull(api.fetchCurrentSemester("synthetic-token"))
        }
        data = "{\"id\":20261}"
        assertEquals(20261, api.fetchCurrentSemester("synthetic-token")?.id)
        assertEquals(6, calls)
    }
}
