#!/usr/bin/env python3
"""
checkpush.py - 审推·CheckPush/Update Automation for Codex Skills
===============================================================
Handles: pre-check, login, push, release, topic setting, audit.
Pre-check runs audit before push; push auto-runs audit as safety gate.
"""

import json, os, sys, time, base64, re, subprocess, socket
import urllib.request

# [P3-防崩溃] Windows GBK 控制台对 UTF-8/emoji 输出会 UnicodeEncodeError → 统一 UTF-8 + replace
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
try:
    import websocket
except Exception:
    websocket = None

# ─── CONFIG (edit these for your environment) ────────────────────────
PROXY = "http://127.0.0.1:3067"
EDGE_DEBUG_PORT = 9222
EDGE_PATH = r"msedge.exe"
TOKEN_FILE = os.path.join(os.path.dirname(__file__), "..", ".gh_token")


# [1.1.0] 插件显示信息文件清单（相对路径：运行版主目录 -> 本地源码库，sync 子命令使用）
PLUGIN_INFO_FILES = [
    "SKILL.md",
    "README.md",
    "AGENTS.md",
    "LICENSE",
    ".codex-plugin/plugin.json",
]

# [1.2.0] 插件资源目录（存在才同步，递归复制）
PLUGIN_ASSET_DIRS = ["assets"]

# [1.3.0] 技能资源目录：同步到 .agents/skills/<skill>/ 下（参照系统自带插件结构，
# 剔除备份/运行状态：.bak/_bak_/.pre_/.err_/_backup_/__pycache__/var/tests）
PLUGIN_SKILL_DIRS = ["engine", "hooks", "config", "references", "agents"]
PLUGIN_SKILL_EXTRA = [
    ("workspace/dgen_rules.md", "workspace/dgen_rules.md"),
    ("requirements.txt", "requirements.txt"),
]
SKILL_DIR_EXCLUDES = (".bak", "_bak_", ".pre_", ".err_", "_backup_", "_test_", "__pycache__", ".pytest_cache")
SKILL_DIR_EXCLUDED_DIRS = ("var", "workspace", ".git")
# [2.0] 用户级/本机配置文件：sync/reinstall 不传播（含个人绝对路径，公开仓库禁用）
PLUGIN_SKILL_CONFIG_EXCLUDES = ("config.toml", "hooks.json")

# ─── [2.0] 敏感信息审计配置 ─────────────────────────────────────────
# SENSITIVE_PATTERNS: 命中即阻断的敏感内容（正则，大小写不敏感）
#   - 个人绝对路径：Windows 用户目录 / 本机便携版路径 / 本机开发目录
#   - 用户名 / token 模式
SENSITIVE_PATTERNS = [
    r"C:\\Users\\[^\\\"']+",          # Windows 用户目录绝对路径
    r"E:\\项目\\Codex_便携版",           # 本机便携版安装路径
    r"E:\\项目\\开发",                   # 本机开发目录
    r"ghp_[A-Za-z0-9]{20,}",                 # GitHub PAT
    r"github_pat_[A-Za-z0-9_]{20,}",         # GitHub fine-grained PAT
    r"gho_[A-Za-z0-9]{20,}",                 # GitHub OAuth
    r"ghs_[A-Za-z0-9]{20,}",
    r"ghr_[A-Za-z0-9]{20,}",
    r"x-access-token:[^\s@]+@",             # token 注入 URL
    r"sk-[A-Za-z0-9]{20,}",                  # OpenAI key 形态
    r"AIza[0-9A-Za-z_-]{20,}",               # Google API key 形态
]

# SENSITIVE_FILENAMES: 被 git 跟踪即阻断的敏感文件（基名/模式匹配）
SENSITIVE_FILENAMES = [
    ".gh_token", ".env", ".npmrc", ".pypirc",
    "id_rsa", "id_ed25519", "*.pem", "*.key",
    "auth.json", "auth.enc", "*.der", "*.pfx",
    "*.token", "*_token*.txt",
]

# SENSITIVE_MAP: sanitize --apply 替换映射（个人路径 -> 占位符，白名单精确替换）
SENSITIVE_MAP = [
    (r"E:\项目\Codex_便携版", r"%CODEX_HOME%"),
    (r"E:\项目\开发", r"%DEV_ROOT%"),
    (r"C:\Users\Administrator", r"$env:USERPROFILE"),
]

# 历史泄露检测模式（git log -S 扫描，命中仅警告——修复需重写历史+force push，人工决策）
HISTORY_SENSITIVE_HINTS = ["Administrator", "Codex_便携版", "E:\\项目\\开发"]

# ─── HELPERS ─────────────────────────────────────────────────────────

def log(msg):
    print(f"[gh-publish] {msg}")

def _proxy_ok():
    """[P3] 检测本地代理是否可用；不可用自动降级直连"""
    try:
        from urllib.parse import urlparse
        u = urlparse(PROXY)
        host, port = u.hostname, u.port or 80
        sock = socket.create_connection((host, port), timeout=2)
        sock.close()
        return True
    except Exception:
        return False

def _run_git(args, cwd, timeout=120):
    """[P3] git 子进程：二进制捕获 + UTF-8 解码（Windows GBK 下 text=True 会 UnicodeDecodeError 崩溃）"""
    r = subprocess.run(args, cwd=cwd, capture_output=True, timeout=timeout)
    out = r.stdout.decode("utf-8", errors="replace")
    err = r.stderr.decode("utf-8", errors="replace")
    return r.returncode, out, err

def _file_hash(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def _copy_if_diff(src, dst, label):
    """Copy src -> dst when content differs (byte-level SHA256). Returns changed(0/1)."""
    if os.path.exists(dst) and _file_hash(src) == _file_hash(dst):
        log(f"consistent: {label}")
        return 0
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(src, "rb") as f:
        data = f.read()
    with open(dst, "wb") as f:
        f.write(data)
    log(f"synced: {label}")
    return 1

def _copy_tree_if_diff(src_dir, dst_dir, label, excludes=(), exclude_dirs=()):
    changed = 0
    for root, dirs, files in os.walk(src_dir):
        dirs[:] = [d for d in dirs if not d.startswith((".", "_")) and d != "__pycache__"
                   and d not in exclude_dirs and not any(pat in d for pat in excludes)]
        for fname in files:
            if any(pat in fname for pat in excludes):
                continue
            s = os.path.join(root, fname)
            rel = os.path.relpath(s, src_dir)
            changed += _copy_if_diff(s, os.path.join(dst_dir, rel), f"{label}/{rel}")
    return changed

def _codex_cli():
    """Locate the Codex CLI binary: env override, portable default, then PATH.
    [2.0] 不再硬编码个人绝对路径（敏感信息）；仅用环境变量 + PATH + 常见相对位置。"""
    env = os.environ.get("CODEX_CLI_PATH")
    if env and os.path.exists(env):
        return env
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "codex.exe")
    if os.path.exists(local):
        return local
    import shutil
    found = shutil.which("codex")
    if found:
        return found
    return "codex"  # 兜底：交给 PATH 解析
    return "codex"

def _bump_cachebuster(plugin_json):
    """Bump version to '<prefix>+codex.<UTC timestamp>' (byte-preserving)."""
    import datetime, re as _re
    with open(plugin_json, "rb") as f:
        data = f.read()
    m = _re.search(rb'"version"\s*:\s*"([^"]+)"', data)
    if not m:
        raise RuntimeError(f"No version field in {plugin_json}")
    ver = m.group(1).decode("utf-8", errors="replace")
    prefix = ver.split("+")[0] if "+" in ver else ver
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
    new_ver = f"{prefix}+codex.{ts}"
    data = data.replace(m.group(0), b'"version": "' + new_ver.encode() + b'"', 1)
    with open(plugin_json, "wb") as f:
        f.write(data)
    log(f"cachebuster: {ver} -> {new_ver}")
    return new_ver

def cmd_reinstall(agents_dir, plugin, marketplace, run_dir):
    """Update .agents plugin source from runtime (main), bump cachebuster,
    then reinstall via `codex plugin add <plugin>@<marketplace>`."""
    log("=" * 50)
    log("REINSTALL PLUGIN: runtime -> .agents source -> codex plugin add")
    log("=" * 50)
    agents_dir = os.path.abspath(agents_dir)
    if not os.path.isdir(agents_dir):
        raise RuntimeError(f"Agents plugin dir not found: {agents_dir}")
    skill_dir = os.path.join(agents_dir, "skills", plugin)
    skills_root = os.path.join(agents_dir, "skills")
    if not os.path.isdir(skill_dir) and os.path.isdir(skills_root):
        existing = [d for d in os.listdir(skills_root)
                    if os.path.isdir(os.path.join(skills_root, d))]
        if existing:
            skill_dir = os.path.join(skills_root, existing[0])
            log(f"skill dir: detected '{existing[0]}' (plugin '{plugin}')")
    src_skill = os.path.join(run_dir, "SKILL.md")
    if not os.path.exists(src_skill):
        src_skill = os.path.join(run_dir, "skills", "SKILL.md")
    if os.path.exists(src_skill):
        _copy_if_diff(src_skill, os.path.join(skill_dir, "SKILL.md"), f"skills/{os.path.basename(skill_dir)}/SKILL.md")
    for rel in ("README.md", "AGENTS.md", "LICENSE", ".codex-plugin/plugin.json"):
        rp = os.path.join(run_dir, rel)
        if os.path.exists(rp):
            _copy_if_diff(rp, os.path.join(agents_dir, rel), rel)
    for d in PLUGIN_ASSET_DIRS:
        rd = os.path.join(run_dir, d)
        if os.path.isdir(rd):
            _copy_tree_if_diff(rd, os.path.join(agents_dir, d), d)
    # [1.3.0] 技能资源目录：参照系统插件 skills/<name>/ 结构（engine/hooks/config/references/agents...）
    base = os.path.basename(skill_dir)
    for d in PLUGIN_SKILL_DIRS:
        rd = os.path.join(run_dir, d)
        if os.path.isdir(rd):
            ex = SKILL_DIR_EXCLUDES + (PLUGIN_SKILL_CONFIG_EXCLUDES if d == "config" else ())
            _copy_tree_if_diff(rd, os.path.join(skill_dir, d), f"skills/{base}/{d}", ex, SKILL_DIR_EXCLUDED_DIRS)
    for rel, dst_rel in PLUGIN_SKILL_EXTRA:
        rp = os.path.join(run_dir, rel)
        if os.path.exists(rp):
            _copy_if_diff(rp, os.path.join(skill_dir, dst_rel), f"skills/{base}/{dst_rel}")
    ver = _bump_cachebuster(os.path.join(agents_dir, ".codex-plugin", "plugin.json"))
    cli = _codex_cli()
    log(f"Reinstalling {plugin}@{marketplace} via {cli} ...")
    r = subprocess.run([cli, "plugin", "add", f"{plugin}@{marketplace}"],
                       capture_output=True, timeout=120)
    out = r.stdout.decode("utf-8", errors="replace")
    err = r.stderr.decode("utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError(f"codex plugin add failed ({r.returncode}): {err.strip() or out.strip()}")
    log(f"Reinstall OK: {plugin}@{marketplace} -> {ver}")
    for line in out.splitlines():
        if line.strip():
            log(line.strip()[:160])

def assert_edge_running():
    try:
        targets = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{EDGE_DEBUG_PORT}/json", timeout=5).read())
        log(f"Edge OK ({len(targets)} targets)")
        return targets
    except Exception:
        log("Starting Edge with CDP...")
        subprocess.Popen([EDGE_PATH, f"--remote-debugging-port={EDGE_DEBUG_PORT}",
            "--remote-allow-origins=*", "--no-first-run", "--new-window", "https://github.com"])
        time.sleep(5)
        return assert_edge_running()

def get_ws_url(targets, url_filter=None):
    for t in targets:
        if t["type"] == "page":
            if url_filter is None or url_filter in t["url"]:
                return "ws://127.0.0.1:9222/devtools/page/" + t["id"]
    for t in targets:
        if t["type"] == "page":
            return "ws://127.0.0.1:9222/devtools/page/" + t["id"]
    raise RuntimeError("No page target found")

class CDP:
    def __init__(self, ws_url):
        self.ws = websocket.create_connection(ws_url, timeout=10)
        self.msg_id = 0
    def cmd(self, method, params=None):
        self.msg_id += 1
        cmd = {"id": self.msg_id, "method": method}
        if params: cmd["params"] = params
        self.ws.send(json.dumps(cmd))
        while True:
            resp = json.loads(self.ws.recv())
            if resp.get("id") == self.msg_id:
                if "error" in resp: raise RuntimeError(f"CDP error: {resp['error']}")
                return resp.get("result", {})
    def js(self, code):
        r = self.cmd("Runtime.evaluate", {"expression": code, "awaitPromise": True})
        return r.get("result", {}).get("value", "")
    def close(self):
        self.ws.close()

def get_cookies_via_cdp(cdp):
    result = cdp.cmd("Network.getAllCookies")
    return {c["name"]: c["value"] for c in result.get("cookies", []) if "github" in c.get("domain", "")}

def read_token():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE) as f: return f.read().strip()
    return None

def save_token(token):
    os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
    with open(TOKEN_FILE, "w") as f: f.write(token)
    log("Token saved")

def api_call(method, path, data=None, token=None, retries=3):
    """[P3] API 调用：代理不可用自动降级直连 + 5xx/网络错误指数退避重试 + JSON 解析容错"""
    import requests
    headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "gh-publish-skill"}
    if token: headers["Authorization"] = f"token {token}"
    proxies = None
    if _proxy_ok():
        proxies = {"http": PROXY, "https": PROXY}
    else:
        log("proxy unavailable -> direct connection")
    url = f"https://api.github.com{path}"
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            r = getattr(requests, method.lower())(url, json=data, headers=headers, proxies=proxies, timeout=30)
            if r.status_code in (502, 503, 504) and attempt < retries:
                log(f"api {method} {path}: HTTP {r.status_code} retry {attempt}/{retries}")
                time.sleep(2 ** attempt)
                continue
            if r.text:
                try:
                    body = r.json()
                except Exception:
                    body = {"raw": r.text[:500]}
            else:
                body = {}
            return r.status_code, body
        except Exception as e:
            last_err = e
            log(f"api {method} {path}: {e} retry {attempt}/{retries}")
            time.sleep(2 ** attempt)
    raise RuntimeError(f"API {method} {path} failed after {retries} retries: {last_err}")

# ═══════════════════════════════════════════════════════════════════
# AUDIT ENGINE
# ═══════════════════════════════════════════════════════════════════


def _git_ignored(repo_dir, rel_path):
    """[P4-20260806] audit 尊重 .gitignore：被 git 忽略的文件不会被推送，不应作为推送门禁拦点。"""
    try:
        r = subprocess.run(["git", "check-ignore", "-q", "--", rel_path.replace(os.sep, "/")],
                           cwd=repo_dir, capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False

def _fnmatch_base(fname, pat):
    """基名匹配：支持 * 通配；匹配成功返回 True"""
    import fnmatch
    return fnmatch.fnmatch(fname.lower(), pat.lower())

def _is_allowed(hit, line):
    """[2.0] 敏感命中豁免：工具自身配置定义 / 文档示例占位符，不算泄露"""
    if "<user>" in hit or "$env:USERPROFILE" in line or "%USERPROFILE%" in line:
        return True
    if "{token}" in line or "{owner}" in line or "your_token" in line:
        return True
    if any(k in line for k in (
        "SENSITIVE_PATTERNS =", "SENSITIVE_MAP =", "SENSITIVE_FILENAMES =",
        "HISTORY_SENSITIVE_HINTS =", "def _scan_sensitive", "def _is_allowed",
        "def cmd_sanitize", "# ─── [2.0] 敏感信息审计配置",
    )):
        return True
    return False

def _scan_sensitive(repo_dir):
    """[2.0] 敏感信息扫描（个人路径/用户名/token/密钥文件）。
    返回 (阻断 issues, 警告 warnings)。issue 元组: (rel, "SENSITIVE", detail)"""
    issues, warns = [], []
    TEXT_EXTS = {".py",".md",".json",".txt",".ps1",".toml",".yaml",".yml",".ini",".cfg",".conf",".js",".ts",".html",".css",".xml",".bat",".cmd",".sh",".env",".gitignore",".yml",".lock"}
    pats = [(re.compile(p, re.IGNORECASE), p) for p in SENSITIVE_PATTERNS]
    # 先查被 git 跟踪的敏感文件名
    rc, out, _ = _run_git(["git", "ls-files"], repo_dir)
    tracked = out.splitlines() if rc == 0 else []
    for rel in tracked:
        base = os.path.basename(rel)
        for sp in SENSITIVE_FILENAMES:
            if _fnmatch_base(base, sp):
                issues.append((rel, "SENSITIVE-FILE", f"tracked sensitive file pattern: {sp}"))
                break
    # 再逐文件扫内容
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if not d.startswith((".", "_")) and d != "__pycache__"]
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, repo_dir).replace(os.sep, "/")
            if _git_ignored(repo_dir, rel):
                continue
            _, ext = os.path.splitext(fname)
            if ext.lower() not in TEXT_EXTS:
                continue
            # [2.0] 工具自身配置块行区间豁免（SENSITIVE_* 定义，非泄露）
            cfg_lines = set()
            if os.path.basename(fpath) == "checkpush.py":
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as _fh:
                        _all = _fh.readlines()
                    for _i, _l in enumerate(_all, 1):
                        if any(_k in _l for _k in ("SENSITIVE_PATTERNS =", "SENSITIVE_MAP =",
                                                   "SENSITIVE_FILENAMES =", "HISTORY_SENSITIVE_HINTS =")):
                            cfg_lines.add(_i)
                            _j = _i + 1
                            while _j <= len(_all) and _all[_j-1].strip() and not _all[_j-1].strip().startswith(("def ", "# ═", "# ─")):
                                cfg_lines.add(_j)
                                _j += 1
                except Exception:
                    pass
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        if i in cfg_lines:
                            continue
                        for rx, pat in pats:
                            m = rx.search(line)
                            if m:
                                hit = m.group(0)
                                if _is_allowed(hit, line):
                                    continue  # 工具配置定义/文档占位符豁免
                                issues.append((rel, "SENSITIVE", f"L{i} ~{pat}~: {hit[:40]}"))
                                break
            except Exception:
                pass
    return issues, warns

def _scan_git_health(repo_dir):
    """[2.0] git 卫生扫描：备份残留被跟踪 / 未忽略敏感文件 / 历史泄露提示。
    返回 (阻断 issues, 警告 warnings)"""
    issues, warns = [], []
    rc, out, _ = _run_git(["git", "ls-files"], repo_dir)
    tracked = out.splitlines() if rc == 0 else []
    BAK_PATS = (".bak", "_bak_", ".pre_", ".err_", "_backup_", "__pycache__", ".pytest_cache")
    for rel in tracked:
        if rel.startswith("tests/"):
            continue  # 测试夹具（_test_dash/_test_war）是设计使然的固定数据，豁免
        low = rel.lower()
        if any(p in low for p in BAK_PATS):
            warns.append((rel, "GIT-BACKUP", "tracked backup/residue file"))
    # 未忽略的敏感文件（若存在且未被 git 忽略 -> 可能被 git add -A 误提交）
    for fname in [".gh_token", ".env", "auth.json", "memory.db"]:
        p = os.path.join(repo_dir, fname)
        if os.path.exists(p) and not _git_ignored(repo_dir, fname):
            issues.append((fname, "GIT-UNIGNORED", "sensitive file exists but NOT git-ignored"))
    # 历史泄露提示（只警告，重写历史需人工决策）
    for hint in HISTORY_SENSITIVE_HINTS:
        try:
            rc2, out2, _ = _run_git(["git", "log", "--all", "--oneline", "-S", hint], repo_dir, timeout=60)
            if rc2 == 0 and out2.strip():
                warns.append(("HISTORY", "GIT-HISTORY", f"history contains {hint!r}: {out2.strip().splitlines()[0][:80]}"))
        except Exception:
            pass
    return issues, warns

def cmd_audit(repo_dir):
    """Audit repository files for encoding/bom issues. Returns (ok_count, issues_list)."""
    STRONG_MOJIBAKE = {0x00a0,0x00a1,0x00a2,0x00a3,0x00a4,0x00a5,0x00a6,0x00a7,0x00a8,0x00a9,0x00aa,0x00ab,0x00ac,0x00ae,0x00af,0x00b0,0x00b1,0x00b2,0x00b3,0x00b4,0x00b5,0x00b6,0x00b7}
    """Audit repository files for encoding/bom issues. Returns (ok_count, issues_list)."""
    STRONG_MOJIBAKE = {0x00a0,0x00a1,0x00a2,0x00a3,0x00a4,0x00a5,0x00a6,0x00a7,0x00a8,0x00a9,0x00aa,0x00ab,0x00ac,0x00ae,0x00af,0x00b0,0x00b1,0x00b2,0x00b3,0x00b4,0x00b5,0x00b6,0x00b7}
    SAFE_CHARS = {0x2018,0x2019,0x201c,0x201d,0x2013,0x2014,0x2026}
    TEXT_EXTS = {".py",".md",".json",".txt",".ps1",".toml",".yaml",".yml",".ini",".cfg",".conf",".js",".ts",".html",".css",".xml",".bat",".cmd",".sh",".env",".gitignore"}
    ok, skipped, issues = 0, 0, []

    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if not d.startswith((".", "_")) and d != "__pycache__"]
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, repo_dir)
            if _git_ignored(repo_dir, rel):
                skipped += 1
                continue
            _, ext = os.path.splitext(fname)
            if ext.lower() not in TEXT_EXTS:
                skipped += 1; continue
            try:
                with open(fpath, "r", encoding="utf-8") as f: text = f.read()
            except Exception:
                issues.append((rel, "ENCODING", "cannot read as UTF-8")); continue
            if not text.strip(): continue
            with open(fpath, "rb") as f: raw = f.read(3)
            if raw[:3] == b"\xef\xbb\xbf":
                # 豁免: .ps1 允许 UTF-8 BOM（Windows PowerShell 5.1 按 ANSI/GBK 解析无 BOM UTF-8 会乱码）
                if not fpath.lower().endswith(".ps1"):
                    issues.append((rel, "BOM", "UTF-8 BOM found"))
                continue
            count_repl = text.count("\ufffd")
            if count_repl > 0:
                issues.append((rel, "REPLACEMENT", f"{count_repl}x U+FFFD")); continue
            non_ascii = [ord(c) for c in text if ord(c) > 127]
            if len(non_ascii) >= 5:
                cjk = sum(1 for cp in non_ascii if 0x4E00 <= cp <= 0x9FFF or 0x3400 <= cp <= 0x4DBF)
                moji = sum(1 for cp in non_ascii if cp in STRONG_MOJIBAKE)
                if moji > 0 and cjk == 0:
                    issues.append((rel, "MOJIBAKE", f"moji={moji} cjk={cjk} non-ascii={len(non_ascii)}")); continue
            lines = text.split("\n")
            for i, line in enumerate(lines):
                s = line.strip()
                if not s or len(s) > 120: continue
                # [P4-20260806] 注释行不判 GARBLED：代码注释中的 ?? 常为乱码特征说明（如规则引擎文档），非真实乱码
                if s.startswith("#") or s.startswith("//"): continue
                if s.count("?") > 3:
                    # SQL VALUES 占位符不是乱码
                    if "VALUES" in s or "INSERT" in s: continue
                    issues.append((rel, "GARBLED", f"L{i+1}: {s[:60]}")); break
            ok += 1

    # [2.0] 敏感信息 + git 卫生 扫描（并入总门禁）
    sens_issues, sens_warns = _scan_sensitive(repo_dir)
    git_issues, git_warns = _scan_git_health(repo_dir)
    issues += sens_issues + git_issues
    warns = sens_warns + git_warns

    print(); print("=" * 60)
    print(f"  AUDIT: {repo_dir}")
    print(f"  OK: {ok} files  |  Issues: {len(issues)}  |  Warnings: {len(warns)}  |  Skipped: {skipped}")
    print("=" * 60)
    if issues:
        print(); print(f"  {'FILE':50s} {'TYPE':15s} DETAIL"); print(f"  {'-'*48} {'-'*15} {'-'*40}")
        for rel, typ, detail in issues:
            print(f"  [!] {rel[:48]:48s} {typ:15s} {detail[:60]}")
        print(f"  >>> {len(issues)} issue(s) found (BLOCKING). Fix before push. <<<")
    elif warns:
        print(f"  >>> {len(warns)} warning(s) (non-blocking, review). <<<")
        for rel, typ, detail in warns[:20]:
            print(f"  [~] {rel[:48]:48s} {typ:15s} {detail[:60]}")
        if len(warns) > 20:
            print(f"  ... and {len(warns)-20} more warning(s)")
    else:
        print(f"  >>> ALL CLEAN. Ready to push. <<<")
    return ok, issues

# [2.0] SANITIZE: 敏感信息自动脱敏（替换为占位符）
def cmd_sanitize(repo_dir, apply=False):
    """Scan + optionally replace personal paths with placeholders.
    --apply 实际替换；不带 --apply 只列出命中行（安全预览）。
    return: (hit_count, replaced_count)"""
    hits, replaced = [], 0
    TEXT_EXTS = {".py",".md",".json",".txt",".ps1",".toml",".yaml",".yml",".ini",".cfg",".conf",".js",".ts",".html",".css",".xml",".bat",".cmd",".sh",".env",".gitignore"}
    # 字面路径使用 re.escape：避免 \项 等无效转义，且防止路径中的正则元字符误匹配
    pairs = [(re.compile(re.escape(pat), re.IGNORECASE), repl) for pat, repl in SENSITIVE_MAP]
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if not d.startswith((".", "_")) and d != "__pycache__" and d != ".git"]
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, repo_dir)
            if _git_ignored(repo_dir, rel.replace(os.sep, "/")):
                continue
            _, ext = os.path.splitext(fname)
            if ext.lower() not in TEXT_EXTS:
                continue
            cfg_lines = set()
            if os.path.basename(fpath) == "checkpush.py":
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as _fh:
                        _all = _fh.readlines()
                    for _i, _l in enumerate(_all, 1):
                        if any(_k in _l for _k in ("SENSITIVE_PATTERNS =", "SENSITIVE_MAP =",
                                                   "SENSITIVE_FILENAMES =", "HISTORY_SENSITIVE_HINTS =")):
                            cfg_lines.add(_i)
                            _j = _i + 1
                            while _j <= len(_all) and _all[_j-1].strip() and not _all[_j-1].strip().startswith(("def ", "# ═", "# ─")):
                                cfg_lines.add(_j)
                                _j += 1
                except Exception:
                    pass
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()
            except Exception:
                continue
            changed = False
            for i, line in enumerate(lines):
                if i + 1 in cfg_lines:
                    continue
                for rx, repl in pairs:
                    if rx.search(line):
                        hits.append((rel, i + 1, rx.pattern))
                        if apply:
                            lines[i] = rx.sub(repl, line)
                            changed = True
                        break
            if changed:
                with open(fpath, "w", encoding="utf-8", newline="\n") as fh:
                    fh.writelines(lines)
                replaced += 1
    print(); print("=" * 60)
    print(f"  SANITIZE: {repo_dir}")
    print(f"  Hits: {len(hits)}  |  Files rewritten: {replaced}  |  Apply: {apply}")
    print("=" * 60)
    for rel, lineno, pat in hits[:50]:
        print(f"  [~] {rel}:L{lineno} ~{pat}~")
    if len(hits) > 50:
        print(f"  ... and {len(hits)-50} more")
    if apply:
        print("  >>> Done. Run pre-check to confirm ALL CLEAN. <<<")
    else:
        print("  >>> Preview only. Re-run with --apply to replace. <<<")
    return len(hits), replaced


# ═══════════════════════════════════════════════════════════════════
# PRE-CHECK: audit + target info confirmation (no push)
# ═══════════════════════════════════════════════════════════════════

def cmd_pre_check(owner, repo, repo_dir):
    """Pre-check: display target info + audit report, no push."""
    log("=" * 50)
    log("PRE-CHECK MODE - No push will be performed")
    log("=" * 50)
    print(f"  Target owner : {owner or '(not specified)'}")
    print(f"  Target repo  : {repo or '(not specified)'}")
    print(f"  Directory    : {repo_dir}")
    print()
    _, issues = cmd_audit(repo_dir)
    if issues:
        print(f"\n  [RESULT] {len(issues)} issue(s) found. Fix before push.")
        return False
    print(f"\n  [RESULT] ALL CLEAN. Ready to push.")
    return True

# ═══════════════════════════════════════════════════════════════════
# PUSH (with auto audit gate)
# ═══════════════════════════════════════════════════════════════════

def cmd_sync(owner, repo, message, repo_dir, run_dir, agents_dir=None, plugin=None, marketplace="personal"):
    """One-shot plugin publish: runtime(main) -> local source repo -> audit gate
    -> git push -> (optional) .agents source + cachebuster + codex plugin add.
    Works for any plugin; not tied to a specific runtime."""
    log("=" * 50)
    log("SYNC PLUGIN: runtime(main) -> local source -> audit -> git" + (" -> reinstall" if agents_dir else ""))
    log("=" * 50)
    run_dir = os.path.abspath(run_dir)
    if not os.path.isdir(run_dir):
        raise RuntimeError(f"Runtime dir not found: {run_dir}")
    changed = []
    for rel in PLUGIN_INFO_FILES:
        rp = os.path.join(run_dir, rel.replace("/", os.sep))
        lp = os.path.join(repo_dir, rel.replace("/", os.sep))
        if not os.path.exists(rp):
            continue
        if os.path.exists(lp) and _file_hash(rp) == _file_hash(lp):
            log(f"consistent: {rel}")
            continue
        os.makedirs(os.path.dirname(lp), exist_ok=True)
        with open(rp, "rb") as f:
            data = f.read()
        with open(lp, "wb") as f:
            f.write(data)
        log(f"synced: {rel} (runtime -> source)")
        changed.append(rel)
    for d in PLUGIN_ASSET_DIRS:
        rd = os.path.join(run_dir, d)
        ld = os.path.join(repo_dir, d)
        if os.path.isdir(rd):
            n = _copy_tree_if_diff(rd, ld, d)
            if n:
                changed.append(d)
    if not changed:
        log("All plugin info files consistent. No sync needed.")
    else:
        log(f"Sync done: {len(changed)} file(s) updated.")
    log("Running audit gate + push...")
    cmd_push(owner, repo, message, repo_dir)
    if agents_dir and plugin:
        cmd_reinstall(agents_dir, plugin, marketplace, run_dir)

def cmd_push(owner, repo, message, repo_dir):
    """Push local changes (auto-runs audit first)."""
    log("=" * 50)
    log("STEP 1/3: Audit")
    log("=" * 50)
    _, issues = cmd_audit(repo_dir)
    if issues:
        log(f"FAILED: {len(issues)} issue(s) found. Fix before push.")
        print()
        print("=" * 60)
        print("  PUSH ABORTED - Audit issues must be resolved first.")
        print("  Run `checkpush.py pre-check --dir <dir>` to re-check.")
        print("=" * 60)
        sys.exit(1)
    log("Audit passed. Proceeding to push.")

    token = read_token()
    if not token:
        raise RuntimeError("No token. Run login first.")

    log("=" * 50)
    log("STEP 2/3: Verify repo")
    log("=" * 50)
    log(f"Verifying repo: {owner}/{repo}")
    status, data = api_call("GET", f"/repos/{owner}/{repo}", token=token)
    if status != 200:
        raise RuntimeError(f"Repository {owner}/{repo} not found (HTTP {status})")
    log(f"Repo exists. Branch: {data.get('default_branch', 'main')}")

    log("=" * 50)
    log("STEP 3/3: Git push")
    log("=" * 50)
    log(f"Directory: {repo_dir}")
    log(f"Message: {message}")

    rc, out, err = _run_git(["git", "add", "-A"], repo_dir)
    if rc != 0: log(f"git add stderr: {err.strip()}")

    # [P3] commit 消息经 UTF-8 临时文件（-F），避免 GBK 下含 emoji/特殊字符的 -m 参数编码崩溃
    import tempfile
    fd, msg_path = tempfile.mkstemp(suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(message)
        rc, out, err = _run_git(["git", "-c", "i18n.commitEncoding=utf-8", "commit", "-F", msg_path], repo_dir)
    finally:
        try:
            os.remove(msg_path)
        except Exception:
            pass
    if out.strip(): log(f"commit: {out.strip()[:200]}")
    if rc != 0 and "nothing to commit" not in err and "no changes" not in err:
        log(f"git commit stderr: {err.strip()[:300]}")
    rc2, out2, err2 = _run_git(["git", "rev-parse", "--abbrev-ref", "HEAD"], repo_dir)
    branch = out2.strip() or "main"

    push_url = f"https://x-access-token:{token}@github.com/{owner}/{repo}.git"
    push_cmd = ["git", "push", push_url, branch]
    if not _proxy_ok():
        # [1.2.0] 代理不可用 -> git push 直连（清除仓库级 http.proxy 配置）
        log("proxy unavailable -> git push direct connection")
        push_cmd = ["git", "-c", "http.proxy=", "-c", "https.proxy=", "push", push_url, branch]
    log(f"Pushing to {owner}/{repo} ({branch})...")
    last_err = None
    pushed = False
    for attempt in range(1, 4):
        rc3, out3, err3 = _run_git(push_cmd, repo_dir)
        if out3.strip(): log(f"stdout: {out3.strip()[:200]}")
        if err3.strip(): log(f"stderr: {err3.strip()[:300]}")
        if rc3 == 0:
            pushed = True
            break
        last_err = err3.strip()
        log(f"push attempt {attempt}/3 failed (exit {rc3}), retrying...")
        time.sleep(2 ** attempt)
    if not pushed:
        raise RuntimeError(f"Push failed after 3 attempts: {last_err}")

    # [2.0] STEP 4: push 后远端同步验证（fetch + rev-list）
    log("=" * 50)
    log("STEP 4/4: Verify remote sync")
    log("=" * 50)
    try:
        _run_git(["git", "fetch", "origin"], repo_dir)
        rc4, out4, _ = _run_git(["git", "rev-list", "--count", "--left-right", f"origin/{branch}...HEAD"], repo_dir)
        log(f"remote vs local: {out4.strip()}  (left=behind right=ahead; '0\t0' = synced)")
    except Exception as e:
        log(f"verify skipped: {e}")
    log("Push successful.")

# ═══════════════════════════════════════════════════════════════════
# RELEASE / TOPICS / LOGIN
# ═══════════════════════════════════════════════════════════════════

def cmd_login():
    targets = assert_edge_running()
    ws_url = get_ws_url(targets)
    cdp = CDP(ws_url)
    try:
        token = ensure_token(cdp)
        log(f"Token obtained: {token[:8]}...")
        log("Login successful.")
    finally:
        cdp.close()

def cmd_release(owner, repo, tag, name, body, prerelease):
    token = read_token()
    if not token: raise RuntimeError("No token. Run login first.")
    data = {"tag_name": tag, "name": name, "body": body, "prerelease": prerelease}
    status, result = api_call("POST", f"/repos/{owner}/{repo}/releases", data=data, token=token)
    if status == 201: log(f"Release created: {result.get('html_url', '')}")
    else: raise RuntimeError(f"Release creation failed (HTTP {status}): {result}")

def cmd_set_topics(owner, repo, topics):
    token = read_token()
    if not token: raise RuntimeError("No token. Run login first.")
    data = {"names": topics}
    status, result = api_call("PUT", f"/repos/{owner}/{repo}/topics", data=data, token=token)
    if status == 200: log(f"Topics set: {result.get('names', topics)}")
    else: raise RuntimeError(f"Set topics failed (HTTP {status}): {result}")

def ensure_token(cdp):
    token = read_token()
    if token:
        status, _ = api_call("GET", "/user", token=token)
        if status == 200: log("Token valid"); return token
        log("Token invalid or expired, re-login...")
    log("Extracting GitHub session cookies from browser...")
    cdp.js("window.location.href = 'https://github.com'"); time.sleep(3)
    cookies = get_cookies_via_cdp(cdp)
    if "user_session" not in cookies:
        log("Not logged in. Opening GitHub login page...")
        cdp.js("window.location.href = 'https://github.com/login'")
        log("Please log in to GitHub in the opened browser window.")
        input("Press Enter after logging in...")
        cookies = get_cookies_via_cdp(cdp)
        if "user_session" not in cookies:
            raise RuntimeError("Login failed: no user_session cookie found.")
    log(f"Logged in as: {cookies.get('dotcom_user', 'unknown')}")
    log("Obtaining personal access token...")
    cdp.js("""(()=>fetch('https://github.com/settings/tokens',{headers:{'Accept':'text/html'}}).then(r=>r.text()).then(h=>{const m=h.match(/ghp_[a-zA-Z0-9]{36}/);if(m)return m[0];return fetch('/settings/tokens/new',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'description=gh-publish-skill-auto&scopes=repo,workflow'}).then(r=>r.text()).then(h2=>{const m2=h2.match(/ghp_[a-zA-Z0-9]{36}/);return m2?m2[0]:''})}) )()""")
    time.sleep(3)
    for _ in range(20):
        token = cdp.js("(()=>{const m=document.body.innerText.match(/ghp_[a-zA-Z0-9]{36}/);return m?m[0]:''})()")
        if token: break
        time.sleep(1)
    if token: save_token(token); return token
    raise RuntimeError("Failed to obtain GitHub token.")

# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="GitHub Publish Automation")
    parser.add_argument("action", choices=["pre-check", "login", "push", "release", "topics", "api", "audit", "sync", "sanitize"],
                       help="Action: pre-check (audit only, no push) | push (auto audit + push) | ...")
    parser.add_argument("--owner", required=False, help="GitHub owner (e.g. linsong-dev)")
    parser.add_argument("--repo", required=False, help="Repository name")
    
    parser.add_argument("--dir", help="Repository directory (default: parent of scripts/)")
    parser.add_argument("--run", help="Runtime (main) directory to sync plugin info from (for 'sync' action)")
    parser.add_argument("--agents", help=".agents plugin source dir to update + reinstall (for 'sync' action)")
    parser.add_argument("--plugin", help="Plugin name to reinstall (e.g. diegin), with --agents")
    parser.add_argument("--marketplace", default="personal", help="Marketplace for reinstall (default: personal)")
    parser.add_argument("--message", default="Update", help="Commit message")
    parser.add_argument("--tag", default="v1.0.0", help="Release tag")
    parser.add_argument("--name", help="Release name (default: same as tag)")
    parser.add_argument("--body", default="", help="Release body/notes")
    parser.add_argument("--prerelease", action="store_true", help="Mark as prerelease")
    parser.add_argument("--apply", action="store_true", help="sanitize: actually replace (default: preview only)")
    parser.add_argument("--topics", nargs="+", help="Repository topics")
    parser.add_argument("--method", help="HTTP method for API call")
    parser.add_argument("--path", help="API path for API call")
    parser.add_argument("--data", help="JSON data for API call")
    args = parser.parse_args()
    if args.dir: REPO_DIR = os.path.abspath(args.dir)
    need_repo = {"push", "release", "topics", "api", "pre-check", "sync"}
    if args.action in need_repo and (not args.owner or not args.repo):
        parser.error(f"--owner and --repo are required for '{args.action}' action")

    if args.action == "pre-check":
        cmd_pre_check(args.owner, args.repo, REPO_DIR)
    elif args.action == "login":
        cmd_login()
    elif args.action == "push":
        cmd_push(args.owner, args.repo, args.message, REPO_DIR)
    elif args.action == "release":
        cmd_release(args.owner, args.repo, args.tag, args.name or args.tag, args.body, args.prerelease)
    elif args.action == "topics":
        cmd_set_topics(args.owner, args.repo, args.topics or ["codex", "codex-skill"])
    elif args.action == "sync":
        if not args.run: parser.error("--run is required for 'sync' action")
        cmd_sync(args.owner, args.repo, args.message, REPO_DIR, args.run, args.agents, args.plugin, args.marketplace)
    elif args.action == "audit":
        cmd_audit(REPO_DIR)
    elif args.action == "sanitize":
        cmd_sanitize(REPO_DIR, apply=args.apply)
    elif args.action == "api":
        token = read_token()
        if not token: raise RuntimeError("No token. Run login first.")
        data = json.loads(args.data) if args.data else None
        status, result = api_call(args.method, args.path, data=data, token=token)
        log(f"API {args.method} {args.path}: {status}")
        print(json.dumps(result, indent=2, ensure_ascii=False))
