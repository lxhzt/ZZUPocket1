# Launch 测试版下载

本目录保存已经在本地签名和核验的 `ZZUPocket-0.33.0-launch.1.apk`，供 GitHub 插件不能直接上传 Release 附件时仍有可下载的安装包。

请优先从仓库 Releases 页面下载对应预发布版本；如果发布工作流不可用，可在当前分支打开 APK 文件，选择 **Download raw file**，并对照 `SHA256SUMS.txt` 检查文件完整性。

支持 Android 12 及以上。用途、停用功能和未验证项详见 [发布说明](../docs/launch-0.33.0-launch.1.md)。

APK 采用本地独立发布密钥签名，后续覆盖升级必须保留同一密钥。密钥和密码只保存在本机被 Git 排除的 `.security-tools/launch-signing/` 内；所有者应将整个目录另行加密备份。
