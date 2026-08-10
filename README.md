<h1 align="center">审推 · CheckPush</h1>

<p align="center">
  <b>Codex 技能发布工具：先审后推，门禁放行</b><br>
  编码预检 · 敏感信息脱敏 · 自动测试 · 门禁推送 · 远端核验
</p>

<p align="center">
  <a href="https://github.com/linsong-dev/checkpush/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License">
  </a>
  <img src="https://img.shields.io/badge/version-2.2.0-brightgreen" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10+-orange" alt="Python">
</p>

---

## 30 秒看懂 CheckPush

把 Codex 技能仓库发布到 GitHub 前，先过一道**自动门禁**：编码（BOM/乱码/替换字符）、语法（JSON/YAML/TOML）、敏感信息（token/个人路径）、git 卫生（CRLF/LF 混用、历史泄露）——有问题退回，通过才推。

> 普通发布：`git add && git commit && git push`（出问题已上公网）
>
> 审推：`pre-check` → `sanitize` → `verify` → `push` → `review`（先审后推，防患未然）

## 功能特性

- **五段式通用流程**：审（audit）→ 洗（sanitize）→ 验（verify）→ 推（push）→ 复（review 远端同步核验）
- **全量编码审计**：BOM / 乱码 / 替换字符 / 编码错误，中文文件乱码问题推送前拦截
- **语法校验**：JSON / YAML / TOML 语法检查 + CRLF/LF 行尾混用检测
- **敏感信息扫描**：token / 凭证 / 个人路径（形如 `盘符:\Users\用户名` 的本地路径）历史泄露检查
- **脱敏工具**：`sanitize` 预览 → `--apply` 自动替换个人路径，含自动备份
- **自动验证**：`verify` 自动运行 pytest + 自检脚本，退出码 0/1
- **门禁推送**：push 自动跑审计门禁 + 分叉检测 + 变更摘要 + push 后直连 fetch 验证
- **插件信息一键同步**：`sync` 把运行版主目录的 SKILL.md / README / LICENSE / plugin.json / assets 同步到源码库并推送
- **最后保障**：`scan-mindol` 扫描记忆库（memory.db）无 token/凭证残留

## 环境要求

- Python 3.10+（仅标准库，`websocket-client` 可选，用于 CDP 浏览器登录）
- git + GitHub 账号（token 放 `.gh_token`，已被 .gitignore 排除，绝不上传）
- PowerShell 5.1+（Windows）

## 安装

```powershell
git clone https://github.com/linsong-dev/checkpush.git
cd checkpush
# 可选：浏览器登录增强
pip install websocket-client
```

将 GitHub token 写入 `.gh_token`（一行，无换行）。

## 快速使用

```powershell
# 1. 预检（只审不推）
python scripts/checkpush.py pre-check --owner linsong-dev --repo my-skill --dir S:\xxx\my-skill

# 2. 推送（自动带审计门禁）
python scripts/checkpush.py push --owner linsong-dev --repo my-skill --dir S:\xxx\my-skill --message "update description"

# 3. 插件信息一键同步（运行版主 → 源码库 → git，可选 --agents + --plugin 重装插件）
python scripts/checkpush.py sync --owner linsong-dev --repo my-skill --dir S:\xxx\my-skill --run E:\xxx\my-skill --message "sync plugin info"

# 4. 单独审计 / 脱敏预览 / 验证
python scripts/checkpush.py audit --dir S:\xxx\my-skill
python scripts/checkpush.py sanitize --dir S:\xxx\my-skill          # 预览
python scripts/checkpush.py sanitize --dir S:\xxx\my-skill --apply  # 实际替换
python scripts/checkpush.py verify --dir S:\xxx\my-skill

# 5. 记忆库敏感扫描
python scripts/checkpush.py scan-mindol
```

## 工作流（五段式）

```text
audit（编码+语法+敏感信息+git卫生）
   ↓ 有问题退回
sanitize（个人路径脱敏，自动备份）
   ↓
verify（pytest + 自检）
   ↓
push（门禁 + 分叉检测 + 变更摘要）
   ↓
review（远端同步核验 0/0）
```

## 项目结构

```text
checkpush/
├── scripts/checkpush.py   主程序（11 个动作）
├── .codex-plugin/         Codex 插件元数据
├── SKILL.md               插件说明与完整命令参考
├── .gh_token              GitHub token（gitignore，绝不上传）
└── LICENSE                Apache 2.0
```

## 安全说明

- `.gh_token` 已被 `.gitignore` 排除，且 `audit` 会扫描历史提交中的 token/凭证泄露
- 个人路径（形如 `盘符:\Users\用户名` 的本地路径）默认在发布前脱敏为占位符，保留本机语义
- 敏感信息只替换 token/凭证类，路径类保留（避免破坏语义检索上下文）

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/linsong-dev">linsong-dev</a></sub>
</p>