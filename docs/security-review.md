# ZZUPocket 安全检查与整改记录

> 后续进展：2026-10-27 的 [无账号复核与整改](security-assessment-20261027.md)、[教务授权调查](security-auth-scope-investigation.md) 和 [本轮执行计划](security-work-plan-20261027.md)。本页保留早期结果，不代表后续源码的最终验证。

> 后续记录（2026-10-26）：[公开前端分析](security-public-frontend-analysis.md)与[应用凭据隔离整改](security-credential-containment.md)。本文下方的测试数量和 APK 哈希属于 2026-10-25 的历史验证，不能作为后续改动产物的验收证据。

日期：2026-10-25。目标仓库：`lxhzt/ZZUPocket1`，基线提交：`e2fb61fd333f66174445350e82cb54d19e3b7c08`。

## 范围与结论边界

本次按 [OWASP MASVS](https://mas.owasp.org/MASVS/) 的存储、密码学、认证、网络、平台、代码质量、抗篡改和隐私分类检查客户端源码、Manifest、构建配置及依赖声明，并进行本地回归验证。

**本记录不是渗透测试认证，也不证明学校服务端或任意已发布 APK 安全。** 未使用真实账号，未运行学校接口脚本，未向学校发起登录、查询、端口扫描、漏洞探测或压力请求。构建下载仅访问源码与软件依赖分发站点。

威胁模型覆盖恶意网络、伪造目标 URL、外部 Intent、会话混用、备份/日志隐私暴露和异常输入导致的资源耗尽；不假定攻击者已控制 Android 系统或学校 TLS 私钥。应用改用独立包名，不会覆盖、迁移或停用手机上可能存在的原版应用。

## 立即隔离的能力

- `SecurityPolicy.FINANCIAL_NETWORK_ENABLED=false`。一卡通令牌交换、账户/房间查询、电量、校园卡余额、交易分类和消费流水均在 `EcardClient` 实际发出请求之前拒绝，包括传入自建 OkHttpClient 的情况。
- 原生网络层只允许精确匹配的 CAS、本科/研究生教务、身份服务 HTTPS 主机，拒绝非 443 端口、用户信息 URL、明文、外站及金融主机。
- 电量 Worker 不再排队，升级启动时取消旧的同名工作；实际执行也先检查禁用策略。今日页不再自动查询余额或电量。
- 电费、校园卡源码及本地历史数据保留；页面说明连接已暂停。未实现或新增充值、转账等接口。
- 图书馆页面不再创建 WebView 或连接明文服务器。所有在线接口诊断入口默认停用，不以“调试版”为理由重新启用。
- 重新开放这些能力必须修改源码并重新审查，应用中没有解禁开关。

## 已确认问题与处理

| 风险 | 证据 | 处理与影响 |
| --- | --- | --- |
| 高：允许 HTTP，且图书馆以 HTTP 启动 | 原 `network_security_config.xml`、`LibraryScreen` | 禁止全应用明文；图书馆暂停。研究生系统如降级 HTTP 则拒绝，可能无法登录，不能回退明文 |
| 高：Cookie 未按 Secure、路径、到期筛选，容器缺少同步 | `GmsCookieJar` | 注入会话限制精确主机和 `/stu`，强制 Secure/HttpOnly，过滤过期和不匹配 Cookie，按名称/域/路径合并，限制容量并同步访问 |
| 高：WebView 可载入任意目标/混合内容 | `GmsProbeDialog` | 仅 CAS/GMS 精确 HTTPS 来源；阻止外站、file/content/javascript 等导航及初始资源请求；禁用混合内容、第三方 Cookie、文件/内容访问和远程调试；SSL 错误取消 |
| 中：退出只清理原生凭据，网页会话残留 | 原退出流程 | 清理 WebView Cookie、WebStorage、缓存、历史及活动页面；关闭页面后销毁 WebView，停止周期探针 |
| 中：令牌以外的隐私数据和网页存储可进入备份 | Manifest 与两个备份 XML | `allowBackup=false`，同时为云备份和设备迁移排除所有应用私有及外部数据域 |
| 中：响应正文和完整 URL 进入诊断日志/错误 | GMS 探针、EAS 诊断、WebView 日志 | 去除响应原文和导航查询值；JSON 结构助手不再输出值；正式版 R8 移除应用 Log 调用。保留的旧诊断源码不可在线运行 |
| 中：响应、周次展开和图片缺少资源边界 | 客户端 `.string()`、GMS 周次解析、壁纸解码 | 原生响应最多 4 MiB（含解压后）；JSON 深度最多 64；周次 1–60；展开最多 100,000 记录；图片输入最多 32 MiB、两维采样至 2048，禁止超限后绕过限制重读 |
| 中：MFA 服务器返回地址未经限制 | `attestBaseUrl` | 验证码等状态只发送到原有 CAS 精确 HTTPS 主机，拒绝用户信息、非标准端口和查询/片段型基址。不新增学校接口 |
| 中：可导出 Activity 接受任意路由字符串 | `MainActivity.consumeWidgetRoute` | 仅允许固定的小组件路由；截图与最近任务预览使用 `FLAG_SECURE` 保护 |
| 中：密码在成功后仍保留于 ViewModel | `LoginViewModel` | 登录完成和销毁时清理密码/验证码引用，禁止重复并发提交。Java/Kotlin String 无法保证物理内存擦除 |
| 中：调试包使用生产签名，release 回落 debug 签名 | `app/build.gradle.kts` | debug 使用独立包后缀与调试签名；无生产密钥时仅生成未签名 release。Gradle 分发包增加官方 SHA-256 校验 |
| 低：通知权限检查与 Compose 状态表达不明确 | Android Lint | 通知前检查权限，并显式捕获权限撤销异常；图片状态改为 remember/LaunchedEffect，保留异步解码与取消语义，不用禁用规则消除告警 |
| 中：全局缓存不具备多账号命名空间 | 原全局 Room/偏好结构 | 安全版使用 `com.zzupocket.app.secure` 独立沙箱，和原版并存；原生学校账号首次成功登录后绑定该安装，暂禁切换。保留所有历史文件，不迁移或删除原版数据 |

令牌继续使用现有 EncryptedSharedPreferences/Android Keystore 保护；未改写学校要求的 RSA/PKCS1 登录协议。客户端读取 JWT `exp` 仅用于过期提示，远端仍负责鉴权；没有把客户端解析当作服务器授权验证。

## 本地验证规范

执行：

```text
python tools/security_static_check.py
gradlew.bat testDebugUnitTest assembleDebug
gradlew.bat lintDebug assembleRelease
```

JDK 17，Android SDK 36。构建需要依赖缓存；不需要学校账号，也不启动应用。新安全测试用拒绝 DNS 的客户端和进程内假传输，**不会创建外部网络连接**。

本次将“中等安全压力”限定为可复现的客户端隔离验证配置，不能外推为真实设备全栈压力认证：

| 验证项目 | 输入/约束 | 通过条件 |
| --- | --- | --- |
| 金融接口隔离 | 10 个公开入口，注入可计数的假客户端 | 均在 DNS/传输前拒绝，传输计数为 0 |
| MFA 信任边界 | 5 类不可信目标，分别发送状态与校验码 | 全部在传输前拒绝，假传输计数为 0 |
| 策略并发 | 16 工作线程、32 批 × 250 次，共 8,000 次 | 30 秒内完成，0 次越过边界，无 DNS |
| Cookie 并发 | 同等 8,000 轮写入、读取、清空组合 | 30 秒内完成，无并发异常、不匹配/过期/HTTP 请求不返回 Cookie |
| 畸形输入 | 固定种子 20261025，10,000 组字符串 | 无未处理异常，无超范围周次 |
| 资源限制 | 未知长度响应、深层 JSON、超限文件、极端图片长宽比 | 本地受控拒绝或有界采样 |
| 配置回归 | Manifest、备份、来源、签名、Gradle 完整性 | `security_static_check.py` 17 项均通过 |

实际执行结果见下方更新记录；测试存在不代表测试已通过。

## 发布前仍需完成的验证

- 真机/模拟器上的 WebView 重定向、POST 导航、资源重定向、Cookie 与退出清理验证。Android 的 `shouldInterceptRequest` 对重定向等有平台边界，仅靠源码无法完整证明运行时行为。
- 用**本地 HTTPS 模拟站**验证无效证书、中间人、明文降级和慢速响应；禁止把学校当测试靶场。
- 真机进程重建、后台切换、持续 CPU/内存测试、系统备份/设备迁移的 OEM 差异验证。
- 最终生产签名包与源码对应关系、依赖库日志的运行时行为仍需复核。本地未签名包已经检查 Manifest、签名缺失和直接日志引用，但不等于任意分发包都已验证。运行时 Maven 清单已导出并查询 OSV；分发校验和漏洞数据库比对不等于所有依赖二进制都已验证。
- 多账号数据库命名空间未实施；当前用单账号限制控制风险。研究生网页登录由学校网页处理，仍需用户确保使用同一学校身份。
- 本地退出不等于学校服务端撤销所有令牌。项目原协议未提供经确认的撤销接口，本次未猜测或探测该接口。
- 本地断开金融接口不会收窄统一认证令牌的服务端权限；如果令牌泄露，其他客户端可能仍能用它访问更多学校服务。具体授权范围本次未对外验证，真正的最小权限需要学校支持受限令牌。
- Room 业务数据仍依赖 Android 私有沙箱和系统存储加密，不能承诺抵抗 root、被控制的系统或物理取证攻击。Keystore、独立签名和混淆也不构成抗篡改认证。
- Lint 的 `HardwareIds` 提示已人工核查：现有 SSAID 仅用于学校 CAS 的设备标识，未新增采集或第三方上报；不能改回所有用户共享的固定设备标识。其余字体单位、布局和排版警告不作为安全认证依据。

## 执行结果

- 离线配置检查：17/17 通过，见 [`security-evidence/static-check.json`](security-evidence/static-check.json)。
- 运行时依赖：debug/release 两种运行时配置并集为 95 个 Maven 坐标，与已查询清单完全一致；2026-10-25 查询 OSV，未返回已收录漏洞条目。见 [`运行时清单`](security-evidence/runtime-dependencies.json) 和 [`OSV 结果`](security-evidence/osv-results.json)。此结论受数据库覆盖范围和查询时间限制，不代表不存在未知漏洞。
- 单元测试：327/327 通过，0 failures、0 errors；其中新增 10 项安全测试。证据见 [`unit-tests.json`](security-evidence/unit-tests.json)。
- 本地并发拒绝 8,000 次耗时 0.203 秒；Cookie 并发操作 8,000 轮耗时 0.151 秒；10,000 组畸形输入耗时 0.638 秒。以上是当前主机的进程内假传输结果，不能推断手机、TLS、WebView 或学校服务的吞吐能力。
- `assembleDebug`：通过。调试包为 `com.zzupocket.app.secure.debug`，不作为生产发布包。
- 构建环境和任务结果见 [`build.json`](security-evidence/build.json)。
- `lintDebug`：通过，0 错误、127 警告、6 提示；未新增忽略配置。规则分类与安全相关说明见 [`lint.json`](security-evidence/lint.json)。
- `assembleRelease`：通过，产物为未签名 APK（6,145,524 字节），官方 apksigner 确认缺失签名，不能直接作为生产安装包发布。SHA-256 为 `2eb7d0d58a15d12e109fa588a884be7c66627c8323cadf07c6cec7fbb295fa7e`。
- 最终 APK：aapt 检查包名、备份、明文、调试和导出组件；压缩后的网络 XML 仍禁止明文且仅信任系统证书。DEX 无 `Log.v/d/i/w/e` 方法引用；仍有库使用的 `println/wtf/isLoggable/getStackTraceString` 引用，未把“常用敏感日志已移除”扩大解释为“所有库都不产生日志”。见 [`release-apk.json`](security-evidence/release-apk.json)。

**验收结论：本次定义的本地隔离与输入压力配置通过；真机全栈动态安全验收尚未完成。** 草稿 PR 保留待复核状态，不宣称通过全面中等强度渗透测试或 MASVS 认证。

## 参考

- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [Android：明文通信风险](https://developer.android.com/privacy-and-security/risks/cleartext-communications)
- [Android：WebView 不安全 URI 加载](https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading)
- [Android：自动备份规则](https://developer.android.com/identity/data/autobackup)
- [OSV 漏洞数据库](https://osv.dev/)
