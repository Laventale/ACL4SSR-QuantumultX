# ACL4SSR → Quantumult X（自用规则同步项目）

**非 ACL4SSR 官方项目。** 本项目从 [ACL4SSR 官方 Online Full 模板](https://github.com/ACL4SSR/ACL4SSR/blob/master/Clash/config/ACL4SSR_Online_Full.ini) 按顺序读取规则源，将官方 Clash `.list` 转为 Quantumult X 可读取的 `.list`。**不涉及机场订阅、节点、证书。**

## 开始：GitHub 上传与运行

1. 创建公开 GitHub 仓库，推荐名称 `ACL4SSR-QuantumultX`，初次创建时不勾选 README。
2. 解压下载的 `ACL4SSR-QX-Starter.zip`，将**解压后的文件与目录（包括隐藏的 `.github` 文件夹）**提交到仓库根目录，而不是直接上传 zip 文件。
3. 推荐用 Git 上传（适合 macOS/Windows，需安装 Git）：

   ```bash
   git clone https://github.com/YOUR_USERNAME/ACL4SSR-QuantumultX.git
   cd ACL4SSR-QuantumultX
   # 复制 Starter 文件夹内的所有内容（包括 .github）到当前目录
   git add .
   git commit -m "Initial ACL4SSR Quantumult X converter"
   git push -u origin main
   ```

   若空仓库的默认分支不是 main，请按实际分支名执行 `git push`。

4. GitHub 仓库 → **Actions** → **Sync official ACL4SSR to Quantumult X** → **Run workflow**。
5. 任务完成后，仓库应自动生成 `Rules/`、`filter_remote.snippet`、`manifest.json` 以及 `conversion-warnings.txt`。
6. 若出现权限错误，到 Settings → Actions → General → Workflow permissions，将权限改成 **Read and write permissions**；如果组织限制不允许，请让仓库管理员开放对应权限。

以后会每天 UTC 03:23 左右自动同步。GitHub Actions 的 `schedule` 可能延迟；公开仓库 60 天不活跃还可能暂停定时任务，必要时手动启动。

## Quantumult X 中替换远程规则（推荐）

1. **在 iPhone 上备份现有可正常使用的 `.conf`**（包含节点密码，绝不要提交到 GitHub）。
2. 打开你 GitHub 仓库中的 `filter_remote.snippet`，复制完整内容。
3. 编辑本地 Quantumult X 配置：**只替换 `[filter_remote]` 与下一节标题之间的内容**。也可以在电脑上运行下方的本地合并命令（不会上传私密配置）。
4. 保留 `[policy]`、`[server_local]`、`[dns]`、`[filter_local]` 等其他部分。不要把 `[filter_remote]` 标题复制两次。
5. 确认 `[policy]` 仍然有模板使用的分组，如 `🚀 节点选择`、`💬 Ai平台`、`🎯 全球直连` 等。若你的配置已使用之前生成的 ACL4SSR Online Full 适配版，名称通常一致。
6. Quantumult X → 分流 / 远程资源，手动刷新一次，确保全部规则集成功加载。可先将 `🛑 广告拦截` 设为 `direct` 观察差异，再恢复需要的策略。

示例地址（将 YOUR_USERNAME 改为真实用户名）：

```
https://raw.githubusercontent.com/YOUR_USERNAME/ACL4SSR-QuantumultX/main/Rules/UnBan.list
```

**注意规则优先级**：官方 ACL4SSR Online Full 按顺序引用多个规则集，生成的 `filter_remote.snippet` 同样保留其先后顺序。Quantumult X 与 Clash 的匹配机制并非完全一致，建议在 Quantumult X 中实际测试关键域名。用户自定义的本地 `host-suffix` 规则、末尾的 `final` 要保留；不要出现两个 `final`。

## 可选：本地自动合并，不必逐条复制

若你的电脑已经有**未脱敏且可连接的** `my_private.conf`，可以在自己电脑上运行：

```bash
python scripts/patch_conf.py my_private.conf filter_remote.snippet
```

生成 `my_private_selfhosted.conf`，只替换 `[filter_remote]`，不改变节点、策略组、DNS 或 MITM。**这份私有文件千万不要上传到 GitHub**。

## 自动转换保障

- 只允许请求 ACL4SSR 官方仓库的 `Clash/` 路径。
- 读取官方 `ACL4SSR_Online_Full.ini` 中 **有效（非注释）的 ruleset=**，不擅自启用注释掉的 `ChinaIp.list`。
- 支持：`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-WILDCARD`、`IP-CIDR`、`IP-CIDR6`、`IP-ASN`、`GEOIP`。
- 针对带 `*` 或 `?` 的域名转换为 `host-wildcard`，避免 `host-suffix, *2.example.com` 无法解析。
- 仅在有 `no-resolve` 的 IP/CIDR 规则上**移除此修饰符并输出警告**。这会存在细微语义差异；对精确 DNS 行为敏感时请查看 `conversion-warnings.txt`。
- 出现未知语法/意外格式、拉取失败、文件数量异常、转换后空文件时，**整个任务失败而不提交**，GitHub 上保留上次有效文件。
- 每次生成 `manifest.json`（来源、策略组、规则数量、SHA256），便于审计；脚本没有生成时间戳以免每天无意义提交。
- 上游规则采用 [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)；再发布时注意署名与相同方式共享许可。

## 手工在电脑运行（可选）

Python 3.11+，无需额外依赖：

```bash
python -m unittest discover -s tests -v
python scripts/convert.py --repo YOUR_USERNAME/ACL4SSR-QuantumultX --branch main
```

命令执行前需要能够访问 `raw.githubusercontent.com`。本地运行后生成的文件需要自己提交。GitHub Actions 无需本地安装 Python。

## 安全提醒

- **只上传此仓库模板**，不要上传带真实节点密码的机场配置。
- `.gitignore` 已忽略 `*.conf`，但它不是安全边界：上传前仍应检查文件列表。
- 机场提供的 MITM 证书 `p12`、passphrase 以及代理节点密码不能公开。
- 如某次转换报错，请在 Actions 的执行日志查看对应规则文件和行号，不要直接忽略不兼容规则。
