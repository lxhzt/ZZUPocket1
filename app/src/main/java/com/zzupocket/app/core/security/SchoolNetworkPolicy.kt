package com.zzupocket.app.core.security

import java.io.IOException
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.Response

/** Exact hosts, TLS only, no user-controlled destination or credential forwarding. */
object SchoolNetworkPolicy {
    val allowedHosts: Set<String> = setOf(
        "cas.s.zzu.edu.cn", "jwxt.zzu.edu.cn", "gmsstu.zzu.edu.cn", "authx-service.zzu.edu.cn",
    )
    val webHosts: Set<String> = setOf("cas.s.zzu.edu.cn", "gmsstu.zzu.edu.cn")

    fun permits(url: HttpUrl, hosts: Set<String> = allowedHosts): Boolean =
        url.isHttps && url.port == 443 && url.host in hosts &&
            url.username.isEmpty() && url.password.isEmpty()

    fun requireAllowed(url: HttpUrl) {
        if (!permits(url)) throw IOException("连接被安全策略阻止")
    }
}

/** Application interceptor: reject before DNS or any network I/O. */
class SchoolNetworkInterceptor(private val service: SchoolService) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        SchoolNetworkPolicy.requireAllowed(chain.request().url)
        val permitted = SchoolRequestPolicy.permits(chain.request(), service)
        if (!permitted) throw IOException("请求超出此功能获准的学校接口范围")
        return chain.proceed(chain.request())
    }
}
