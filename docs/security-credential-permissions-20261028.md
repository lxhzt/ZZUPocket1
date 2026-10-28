# 学校凭据类型与权限核查

> 同日后续：已经找到学校正式开放平台的应用级 scope 和具体教务权限候选，见[受限授权核查](security-restricted-academic-auth-20261028.md)。这不改变本文对当前 App 通用 CAS 凭据的判断；新权限尚未申请或获批。

日期：2026-10-28。依据：当前工作区源码、学校公开页面与静态主脚本。未使用学生账号，没有获得或验证真实用户令牌。

## 结论

**当前本科原生查询使用的是统一认证返回的 idToken，项目把它命名为 userToken；不能把它认定为教务专用凭据。** 原代码明确把同一个值传给一卡通会话兑换入口，学校当前公开的一卡通脚本也仍采用 tid → 专用 accessToken 的二级登录设计。本轮没有执行兑换，因此这是一条有代码和当前静态协议支持的跨服务风险路径，不能扩写成“今天已经实测可扣款”。

**学校教务网页使用 Cookie，不自动意味着取得了权限隔离。** 研究生入口在未登录时已经设置 `cn_com_southsoft_gmis_stu`，随后返回 302 到 CAS。Cookie 名称、UUID 形状、Domain/Path 或是否存在，都不能单独证明身份已认证、只读或不能跨服务兑换。

## 凭据分类

| 对象 | 类型及代码中的用途 | 当前应用如何处理 | 权限判断与证据限制 |
|---|---|---|---|
| 学校账号、密码 | 统一身份认证的原始认证材料；CasClient 用公开 RSA 公钥加密后提交认证流程 | 登录时短暂接触，不持久化密码 | 不是教务专用授权；加密传输不缩小登录后能取得的权限。本轮未提交任何值 |
| CAS `idToken` / 项目 `userToken` | `CasClient.login` 将返回的 `data.idToken` 原样作为 `LoginResult.userToken`；EasClient 放进 `Authorization` | 仍加密保存，供本科查询复用 | 属于高影响认证材料；原项目还用同值发起一卡通兑换和门户校园卡余额查询。未取得真实载荷，不能声称已核实 `aud`、`scope`、有效期、签名算法或服务端执行规则 |
| CAS `refreshToken` | 统一认证登录同时返回的刷新材料 | 当前 persist 置空，存储初始化移除历史闲置刷新值 | 刷新能力及撤销策略属于服务端未知项；不因当前未使用就把它视为无风险 |
| MFA `state` / `gid`、短信码 | 一次认证过程的状态/挑战材料；与检测、发送、校验、最终登录关联 | 临时用于登录编排 | 不是教务业务令牌，也不是资金权限隔离依据；本轮未触发这些接口 |
| CAS 全局 Cookie（如 TGC、SESSION） | 按 CAS 机制，可能代表能够为其他服务取得票据的 SSO 状态 | 当前 GMS 导入过滤这些名称，登录完成后清理浏览器会话 | 未取得学校登录后样本，具体名称与权限未知；不能复制给教务原生客户端并声称权限变小 |
| 标准 CAS service ticket | 标准规定为目标服务绑定、单次验证的票据 | 研究生/本科网页登录回调路线采用 CAS 形式；本轮只观察入口 | 标准要求不等于学校实现已验证；本轮未拿到实际票据、未调用验证接口 |
| 本科 H5 URL 的 `ticket` 参数 | 本次主脚本在某分支将它按三段形式解码，取载荷里的 `idToken`；还接收 `idToken`、`userToken`、`token` 参数 | 现有原生查询不需要执行此 H5 | **该参数名不能直接等同标准 CAS 的 ST 票据。** 静态代码显示它在这个分支是携带 idToken 的包装；不能据此认为丢弃外层 ticket 后只剩受限教务权限 |
| 本科网页登录应用 Cookie | 另一条当前公开 CAS → `/student/sso/login` 路线的候选会话 | 尚未替代原生 CAS JWT 查询 | 本轮没有登录后样本；不能确认其名称、只读范围、是否可换取其他会话或能否覆盖全部查询 |
| `cn_com_southsoft_gmis_stu` | 研究生应用会话标识，项目也从 UUID 形状提取路由 guid | 只导入该名称，限定 GMS 请求目的地，分离本地课表分区 | **本轮观察到未登录即签发。** 只能证明存在预认证会话上下文，不能把它当作已认证身份；后续登录是否升级同值、是否轮换及实际权限均未测试 |
| 一卡通 `tid` | 原项目从 CAS userToken 兑换所得的跳转中提取，再用它取得一卡通令牌；当前一卡通 JS 仍读取 tid 并调用 gainToken | 所有此类入口先被资金开关拒绝，原代码保留 | 具有会话交换价值，不能当作普通页面参数；未核实一次性、时效和绑定规则，本轮未获取 tid |
| 一卡通 `accessToken` / `refreshToken` | 一卡通自己的访问/刷新材料；JS 把 accessToken 放入请求 Authorization | 当前不取得、不保留闲置值，资金网络拒绝请求 | 专用令牌存在不代表上游统一凭据不能换取它；是否要求额外支付认证须另有服务端证据，本轮未访问业务接口 |
| `/token/jwt/publicKey` 返回值 | 公开 PEM 公钥；本次响应 444 字节、Base64 解码后 DER 294 字节；当前 CasClient 用它加密账号/密码 | 公钥不是用户秘密或登录凭据 | 地址带 jwt 不代表它已被证明是 JWT 验签公钥；代码显示其密码加密用途，本轮未做签名或认证操作 |

“约一个月”“45 分钟”等时长在旧注释中属于历史协议经验；本轮没有登录后样本，不把这些数字登记为当前服务器已确认的属性。

## 当前数据流与风险

```text
统一账号/密码
  └─ 统一认证登录（本轮不执行）
       └─ data.idToken = 项目 userToken
            ├─ 本科 EAS Authorization（现有正常功能）
            ├─ 原项目的一卡通余额 X-Id-Token（当前关闭）
            └─ 原项目的一卡通会话兑换（当前关闭）
                  └─ tid → 一卡通 accessToken / refreshToken

CAS 网页登录（另一种入口，本轮仅观察未登录页面）
  └─ 目标服务回调 → 应用自己的会话 Cookie（实际权限待证实）
```

代码依据：

- `app/src/main/java/com/zzupocket/app/data/auth/CasClient.kt`：`ensurePublicKey`、`detectMfa`、`login`、固定 appId `com.supwisdom.zzu`，没有请求一个专门的“教务只读 scope”。appId 相同也不单独证明后台权限相同。
- `app/src/main/java/com/zzupocket/app/data/auth/AuthRepository.kt`：`persist`、`requireCasToken`、`requireEcardAccessToken`，同一个 userToken 的保存、教务复用和原一卡通兑换编排；兑换前已执行资金限制。
- `app/src/main/java/com/zzupocket/app/data/eas/EasClient.kt`：常规教务请求把 userToken 放入 Authorization。
- `app/src/main/java/com/zzupocket/app/data/ecard/EcardClient.kt`：`fetchTid`、`fetchTokens`、`rawCardBalance`，七处底层金融传输及公开方法均有拦截；本轮不调用它们。
- `app/src/main/java/com/zzupocket/app/data/gms/GmsCookie.kt`：只保留应用 Cookie 的过滤是客户端最小化措施，不是服务器授权证明。

学校当前公开脚本补充了两点：本科主脚本将接收的同一 token 写到多个存储名并用于 Authorization；一卡通主脚本从 tid 换取本系统令牌，再放入 Authorization。因此，**名称和请求头不同，不能作为彼此权限隔离的证据。** 本科主脚本中删除宽域 Cookie 的代码也不能证明 CAS 服务器撤销了该凭据。

## 本轮程序访问及证据

按[先行计划](security-credential-permissions-plan-20261028.md)执行，完成 **7 次正常 HTTPS GET、共 1,238,253 字节响应体**。其中五个为已知公开资源、两个为页面明确引用的主脚本；没有自动跟随 302、保存或回传 Cookie、执行 JS、提交登录表单、发送伪造凭据或调用资金业务。另有一次受限环境的套接字连接在本机被拒绝，不属于已成功到达学校的访问。

| 资源 | 状态 | 观察 |
|---|---|---|
| CAS `/token/jwt/publicKey` | 200 | 公开 PEM，与 CasClient 的密码加密入口对应，不是用户令牌 |
| CAS 带本科 service 的登录页 | 200 | 公开登录表单，没有取得登录后令牌或 scope 契约 |
| 本科 `/uniapp/index.html` | 200 | 页面引用当前 `index.fb0cf6d5.js` |
| 研究生 `/stu/` | 302 | 发出应用 Cookie 后跳转 CAS；跳转没有跟随，Cookie 没有回传 |
| 一卡通 `/` | 200 | 仅静态 H5 壳，引用 `index.c1a092dd.js` |
| 本科主 JS | 200 | token 参数接收/存储/Authorization；`ticket` 某分支解析 idToken |
| 一卡通主 JS | 200 | tid → gainToken；保存访问/刷新令牌；Authorization 携带本系统令牌 |

哈希、脱敏响应属性及必要代码位置见[机器证据](security-evidence/credential-permissions-20261028.json)。原始文件保留在忽略目录 `.security-tools/credential-review-20261028/authorized-public-seeds/`，没有提交原始页面或 Cookie 值。一卡通主脚本与 2026-10-26 记录的 SHA-256 相同，不能把本轮静态读取称为一次新的业务操作验证。

研究生预认证 Cookie 的这次 Set-Cookie 没有显式 Secure，包含 HttpOnly 和 SameSite。这里没有通过 HTTP 发送它，也未取得登录后凭据；不能直接据此宣称资金或个人信息已经泄露。App 当前主动限制 HTTPS，并把导入的原生 Cookie 设为 Secure。这不会替学校证明登录后 Cookie 的安全属性。

## 权限判断的标准与尚未取得的证据

[RFC 7519 第 4.1.3 节](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3)定义 JWT 的 aud 接收方及接收方校验要求，但 aud 本身为可选声明。没有真实令牌时，不能断言学校一定存在、缺少或正确校验这些字段；即使读到字段，也仍需服务端拒绝跨服务使用的证据。

[CAS 2.0 规范第 3.1.1 节](https://apereo.github.io/cas/8.0.x/protocol/CAS-Protocol-V2-Specification.html)要求 service ticket 绑定服务且单次验证；全局 SSO 会话与 service ticket 是不同对象。本科 H5 自定义的 ticket 参数不能仅凭名称套用这项保证。

当前可以排除的误判：公钥等于用户令牌；idToken 与 userToken 必定是两个权限不同的值；专用 accessToken 代表上游不存在兑换能力；预认证 Cookie 存在代表已登录；service 参数或请求头名称代表资金隔离。

当前仍未证明：学校是否允许该 CAS JWT 在今天完成一卡通兑换；对应账户是否需要额外认证；各类令牌的实际签发、撤销、轮换和设备绑定；本科/研究生应用 Cookie 是否绝不跨服务兑换；真实支付、免密、付款码或密码找回的后端执行规则。这些未知项不通过真实支付、伪造令牌或扩大未登录探测来推断。

## 对应用的下一步要求

1. 继续保持金融入口和兑换链关闭，不能因为接口需要另一个 token 就宣称隔离已经完成。
2. 将现有 CAS userToken 按可能跨服务使用的高影响秘密保护；不把删除校园卡代码作为降低其服务器权限的措施。
3. 候选教务网页会话必须分别证明“已认证”“仅必要教务权限”“不能换取资金权限”；不以 Cookie 名、UUID 或 HTTP 200 替代这些条件。
4. 优先寻找学校明确的受限授权说明和不接触统一密码/全局令牌的接入方式。证据未齐时，保留风险结论，不承诺完整在线功能在凭据被窃取后仍与资金绝缘。
