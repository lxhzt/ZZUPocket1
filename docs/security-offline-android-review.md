# 离线 Android 实验审查记录

日期：2026-10-28。对应[实验计划](security-offline-android-plan.md)。

## 当前结论

**专用实验包、测试包和执行工具已准备；本机模拟器未成功进入可执行实验的状态。Android 运行断言实际执行 0 项，不能记为通过。** 三次启动尝试中，后两次监控记录均显示进程退出，退出码为 `-1073741819`（`0xC0000005`）。目前没有足够证据确定异常根因。

尚未取得实验 App 安装到可用设备、运行时权限检查、setup/verify 两阶段报告或窗口证据。构建成功、APK 清单无联网权限、执行脚本语法检查和本地 APK 预检查都属于准备证据，不能替代 Android 运行结果。

正式应用回归正在执行；`production-regression.log` 的最终结果、当前 APK 哈希与发布隔离检查**待补齐**。本记录不把先前源码的通过结果用于证明新增实验代码或验证器已经通过最终检查。

## 已取得的准备证据

以下原始文件位于工作区 `.security-tools/android-lab-20261028/`，不随 Git 提交。需要发布审计证据时，应另外保存对应摘要和实际文件哈希。

| 项目 | 当前证据 | 可支持的判断 |
|---|---|---|
| 官方包选择 | `sdk-package-selection.json`、`repository2-1.xml`、`aosp-sys-img2-1.xml` | 已取得 Google 官方元数据，选定 Windows Emulator 37.2.12 与 AOSP API 31 x86_64 包；元数据公布的是 SHA-1，不冒充官方 SHA-256 |
| SDK 安装 | `sdk-install.log`、`environment.json`、`emulator-version.txt` | 工作区 SDK 已安装模拟器与镜像；实际程序版本为 37.2.12.0，build 16428233 |
| 加速条件 | `emulator-accel-check.txt`、`environment.json` | 加速检查报告 hypervisor driver 未安装；本阶段没有安装驱动、启用 Windows 特性或修改主机防火墙 |
| 实验构建 | `lab-build.log` | `assembleSecurityLab` 与 `assembleSecurityLabAndroidTest` 构建成功，日志耗时 10 分 31 秒；只证明构建完成 |
| 实验 APK | `lab-apks.json`、`target-manifest-dump.txt`、`test-manifest-dump.txt` | 记录实验与测试包名、两包均未声明 INTERNET、签名验证及 APK 哈希；不是运行时权限与行为验证 |
| 执行工具 | `tools/run-offline-android-security.ps1`、本地预检查记录 | 已编写仅面向本任务 AVD 的固定包执行流程；尚未取得真实设备执行结果 |

安装日志将 AOSP 镜像标为 **SDK 包 revision 5**，`environment.json` 引用的包内 `source.properties` 则写 **`Pkg.Revision=3`**。两者是不同来源的记录，不能默默改成一致，也不能单凭差异认定安装包遭到篡改。复现时应同时保留官方选择清单、SDK 包元数据和包内属性。

`avd-create.log` 还包含 SDK 包位置与工具推断位置不一致的警告；模拟器日志找到的 `systemPath` 是本项目实际 SDK 镜像路径。该警告应保留，不能直接解释为本次异常根因。

## 启动尝试及其限度

| 尝试 | 配置与记录 | 观察结果 |
|---|---|---|
| 第一次 | `emulator-process.json`、`emulator-stdout.log`；无头、软件 CPU、`-gpu software`，请求 1536 MiB、2 核 | 日志明确把 RAM 提升至 2048 MiB；出现软件加速警告和连接本机 ADB 5037 失败。该启动记录自身未提供完整终止状态，不能据此声明仍在运行或已成功启动 |
| 第二次 | `emulator-monitored-process.json`、对应 stdout；控制器持续监控，2048 MiB、2 核、900 秒上限 | 5.31 秒后记录 `all_owned_processes_exited`，退出码 `0xC0000005`；没有开机完成或实验执行报告 |
| 第三次 | `emulator-no-vulkan-process.json`、对应 stdout；`-gpu swiftshader -feature -Vulkan`，2048 MiB、2 核、900 秒上限 | 日志确认 Vulkan 被禁用；10.42 秒后同样记录进程退出及 `0xC0000005`，没有进入实验执行阶段 |

第三次调整采用[Android 官方故障排查说明](https://developer.android.com/studio/run/emulator-troubleshooting)中的关闭 Vulkan 方式，属于一次有界配置排除。相同异常码既不能证明漏洞位于应用，也不能确定是 GPU、驱动、镜像或其他宿主兼容性问题；关闭 Vulkan 后仍失败也不能排除所有图形路径问题。

执行脚本计划使用独立 ADB server **5038** 和 `emulator-5560`。前两次模拟器日志实际出现的是 **连接 ADB 5037 失败**，不能把脚本的计划参数描述为已经完成的运行事实。后续重试前必须重新核实工具与模拟器使用的 server 配置，不接触其他设备。

三个网络捕获文件目前各 24 字节。这些启动阶段文件不足以证明模拟器、宿主或全部协议没有外网连接。本阶段没有建立模拟器整体网络隔离；实验 App 的预定防护是两 APK 移除 INTERNET、专用 Application 不启动业务调度、WebView 禁止网络加载和虚构输入。由于本次 App 没有进入执行阶段，**运行时的这些门槛也尚未实际验证**。

未使用学校账号、手机、令牌或真实 Cookie；本阶段没有新增学校访问。未读取或导出原始 minidump 内存；`crash-summary.json` 没有可用于确定根因的近期转储条目。

## 验证器审查与待完成整改

对验证器本身的审查发现，必须防止“工具退出成功”或“某个安全标记存在”被误报为实验通过：

1. **完整报告门槛。** setup/verify 必须包含规定的全部检查、阶段和身份；验证相同 runId 的冷进程标记，不能只依赖 `adb` 退出码、`lab_passed=true` 或非空检查列表。结构化返回与固定私有文件导出应一致。
2. **发布变体守卫。** release 签名与实验变体隔离的校验应覆盖边界情形，避免把实验构建、调试签名或实验入口带入正式发行。
3. **窗口证据定位。** 窗口属性检查应绑定本次实际实验 Dialog；不能因为窗口转储中其他窗口出现安全标记，就判定实验 Dialog 已受保护。

上述问题正在整改，最终源码复核与构建/回归结果**待补齐**。没有真实 Android 结果之前，不给这些门槛填写“运行通过”。

## 完成度与后续门槛

| 原计划项目 | 本次状态 |
|---|---|
| 构建专用 APK 与静态检查实验权限 | 已取得准备证据；最终改动后仍须复核 |
| 安装到可用 AVD 并检查双包运行时权限 | 未完成 |
| TokenStore 冷进程恢复、会话分区与计数器持久化 | 未执行 |
| 实际 Cookie/WebStorage 清理 | 未执行 |
| 真实 Dialog、WebView、窗口与合成遮挡触摸 | 未执行 |
| Android 上真实 Room 数据库的分区实验 | 未执行 |
| 导出 setup/verify JSON 与当前 Dialog 窗口证据 | 未取得 |
| 正式变体最终构建、既有回归与产物哈希 | 执行中，待补结果 |

本机不具备已验证可用的实验运行环境。保留工具和失败证据，后续应在具备可用加速能力的既有环境或另行批准的设备环境复验，不为通过测试而擅自安装驱动、修改系统特性、降低隔离门槛或连续无界启动。

即使后续实验通过，模拟器结果也不证明真实硬件 Keystore 能力、断电原子性、历史数据安全擦除、全部覆盖层/辅助服务攻击、学校服务器撤销能力或学校授权范围。真实用户登录兼容性、正式所有者签名及资金安全边界仍需各自的证据；本轮不能宣称完整中等强度安全验收或资金安全保证。

## 最终验证补充位

- 正式构建与回归：待 `production-regression.log` 完成并核对。
- 验证器整改与静态守卫：待最终源码与检查结果核对。
- 当前实验/正式 APK 哈希、签名和 Manifest 复核：待最终构建后填写。
- Android 运行断言：**0 项实际执行，无通过结果**。
