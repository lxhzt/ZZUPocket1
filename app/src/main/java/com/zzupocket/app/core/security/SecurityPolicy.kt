package com.zzupocket.app.core.security

import com.zzupocket.app.core.AppError

/** Re-enabling a capability requires a code change and security review. */
object SecurityPolicy {
    const val FINANCIAL_NETWORK_ENABLED = false
    const val LIBRARY_ENABLED = false
    const val NETWORK_DIAGNOSTICS_ENABLED = false
    const val FINANCE_PAUSED = "电费、校园卡及相关账户接口已暂停连接。历史数据仅供离线查看。"
    const val LIBRARY_PAUSED = "图书馆连接已暂停，等待学校提供可验证的 HTTPS 访问方式。"

    fun requireFinancialNetwork() {
        if (!FINANCIAL_NETWORK_ENABLED) throw AppError.SecurityRestriction(FINANCE_PAUSED)
    }

    fun requireDiagnostics() {
        if (!NETWORK_DIAGNOSTICS_ENABLED) {
            throw AppError.SecurityRestriction("在线接口诊断已停用；安全测试仅使用本地模拟服务。")
        }
    }
}
