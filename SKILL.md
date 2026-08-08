---
name: checkpush
description: "Check before push. Audit encoding (BOM/mojibake/replacement chars), then push to GitHub. Workflows: pre-check (audit only, no git), push (auto audit gate + git push), and sync (runtime main -> local source -> audit gate -> git push in one shot)."
---

# 审推·CheckPush

## 插件信息

| 字段 | 内容 |
|:-----|:------|
| **🔧 功能** | 自动化发布/更新 Codex 技能仓库到 GitHub。推送前编码预检门禁：先审后推，有问题退回，通过才推。支持插件信息同步（运行版主 → 本地源码 → 审推 → git 一步到位）。 |
| **👤 开发者** | linsong-dev |
| **📂 类别** | Productivity |
| **🏷️ 版本** | 1.2.0 |
| **🌐 网站** | [github.com/linsong-dev/checkpush](https://github.com/linsong-dev/checkpush) |

## 工作流程（两步走）

### 第一步：预检（不推送）

```powershell
python scripts/checkpush.py pre-check --owner linsong-dev --repo my-skill --dir S:\xxx\my-skill
```

执行内容：
1. 显示目标信息（owner / repo / 目录）
2. 全量文件编码审计（BOM / 乱码 / 替换字符 / 编码错误）
3. 报告问题清单
4. **不执行任何 git 操作**

---

### 第二步：推送（自动包含审计门禁）

```powershell
python scripts/checkpush.py push --owner linsong-dev --repo my-skill --dir S:\xxx\my-skill --message "update description"
```

执行内容：
1. **STEP 1/3: 自动跑全量审计** → 有问题立即中止，报错退出
2. **STEP 2/3: 验证 GitHub 仓库是否存在**
3. **STEP 3/3: git add → commit → push**

---

### 第三步：插件信息同步（sync，一步到位）

```powershell
python scripts/checkpush.py sync --owner linsong-dev --repo my-skill --dir S:\xxx\my-skill --run E:\xxx\my-skill --message "sync plugin info"

# 一键化（含插件重装）：追加 --agents 插件源 + --plugin 插件名
python scripts/checkpush.py sync --owner linsong-dev --repo my-skill --dir S:\xxx\my-skill --run E:\xxx\my-skill --agents C:\Users\<user>\.agents\plugins\my-skill --plugin my-skill --message "sync plugin info"
```

执行内容：
1. 对比运行版主目录与本地源码库的插件显示信息文件（SKILL.md / README.md / AGENTS.md / LICENSE / .codex-plugin/plugin.json）+ 资源目录（assets/）
2. 以运行版主为准，把不一致的文件同步到本地源码库
3. **自动跑全量审计门禁** → 有问题立即中止，报错退出
4. git add → commit → push 一步到位
5. 提供 `--agents` + `--plugin` 时：同步 .agents 插件源（skills/README/AGENTS/LICENSE/assets）→ bump cachebuster → `codex plugin add <plugin>@<marketplace>` 重装

> 通用工具，不绑定任何特定插件：`--run` 指向运行版主目录，`--dir` 指向本地源码库即可。

---

## 其他命令

| 命令 | 用途 |
|:-----|:------|
| `login` | Edge CDP 浏览器登录 GitHub 获取 token |
| `release` | 创建 Release |
| `topics` | 设置仓库话题 |
| udit | 单独跑编码审计 |
| sync | 插件信息同步：运行版主 → 本地源码 → 审推 → git 一步到位 |

## 已执行的工作

| # | 日期 | Commit | 工作内容 |
|:-:|:----|:-------|:---------|
| 1 | 2026-07-11 | `9ece28c` | 规则文件格式修复 — plain list，引擎加载 55 条规则 |
| 2 | 2026-07-11 | `05bff50` | 规则整理 — 补充 3 条规则，成功模式去重，AGENTS.md 13→16 |
| 3 | 2026-07-10 | 86f3cce | 编码规则同步 + 乱码修复 |
| 4 | 2026-08-07 | `d912916` | 新增 sync 插件信息同步（运行版主→本地源码→审推→git 一步到位）+ 插件信息 1.1.0 |
| 5 | 2026-08-08 | `610aebe` | sync 一键化：assets 资源同步 + --agents/--plugin 重装（.agents 源→cachebuster→codex plugin add）；参照系统自带插件结构补齐插件包（README/AGENTS/LICENSE/assets）+ 插件信息 1.2.0 |
| 6 | 2026-08-08 | `932c2c5` | 一键化加固：代理不可用 git push 直连 + 技能目录自适应检测 + utcnow 弃用修复；diegin/mindol 插件包已按系统结构补齐并重装 |

> 已发布：1.2.0（`610aebe` + `932c2c5`，2026-08-08）

## Configuration

```python
PROXY = "http://127.0.0.1:3067"
EDGE_PATH = r"msedge.exe"
TOKEN_FILE = ".../.gh_token"
```

## Troubleshooting

| Issue | Fix |
|:---|:---|
| Audit 发现问题 | 修复后重跑 pre-check |
| Push 被审计门禁拦截 | 修复报告中列出的问题 |
| "No token" | 先跑 login |
| Edge 无法启动 | 检查 EDGE_PATH |
| Git push 超时 | 检查代理配置 |
