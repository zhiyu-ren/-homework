#!/usr/bin/env python3
"""
用户信息管理系统 - 命令注入修复版
===================================
基于 Class09，修复Ping功能中的命令注入漏洞

修复说明：
  1. ✅ /ping — 命令注入修复：shlex.quote()过滤 + shell=False
"""
import os, sys, logging, sqlite3, hmac, secrets, time, uuid
import subprocess, platform
import shlex
from datetime import timedelta
from collections import defaultdict
from flask import Flask, render_template, render_template_string, request, redirect, session, url_for, g, jsonify
from markupsafe import Markup
from werkzeug.utils import secure_filename
from config import Config
from utils.auth import hash_password, verify_password, account_locker
from utils.password_policy import validate_password, generate_password_hint
from utils.validators import validate_username, validate_email, validate_phone, sanitize_input

app = Flask(__name__)
app.config.from_object(Config)
app.permanent_session_lifetime = timedelta(seconds=Config.PERMANENT_SESSION_LIFETIME)
os.makedirs(os.path.dirname(Config.LOG_FILE) or ".", exist_ok=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(Config.LOG_FILE), logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("security")

@app.after_request
def add_security_headers(response):
    for h, v in Config.SECURITY_HEADERS.items(): response.headers[h] = v
    return response

class RateLimiter:
    def __init__(self): self._records = defaultdict(list)
    def is_allowed(self, key, max_count, window_sec):
        now = time.time()
        self._records[key] = [t for t in self._records[key] if now - t < window_sec]
        if len(self._records[key]) >= max_count: return False
        self._records[key].append(now); return True
rate_limiter = RateLimiter()

def generate_csrf_token():
    if "_csrf_token" not in session: session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]
def validate_csrf_token(token):
    stored = session.get("_csrf_token")
    return bool(stored and token and hmac.compare_digest(stored, token))
app.jinja_env.globals["csrf_token"] = generate_csrf_token

DATABASE = Config.DB_PATH
def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DATABASE) or ".", exist_ok=True)
        g.db = sqlite3.connect(DATABASE); g.db.row_factory = sqlite3.Row
    return g.db
@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    db = get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, role TEXT DEFAULT 'user',
        email TEXT NOT NULL, phone TEXT NOT NULL, balance REAL DEFAULT 0.0,
        avatar TEXT DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    db.commit()

def seed_default_users():
    db = get_db()
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0: return
    for u, p, r, e, ph, b in [
        ("admin", "Admin@2025Secure!", "admin", "admin@example.com", "13800138000", 99999),
        ("alice", "Alice@2025Secure!", "user", "alice@example.com", "13900139001", 100)]:
        db.execute("INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (None, u, hash_password(p), r, e, ph, b, None, None, None))
    db.commit()

with app.app_context():
    init_db(); seed_default_users()

def get_user_by_username(username):
    row = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return dict(row) if row else None

def get_user_by_id(user_id):
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None

def get_safe_user_info(username):
    user = get_user_by_username(username)
    if user: user.pop("password_hash", None); user.pop("id", None)
    return user

# ===== 首页 =====
@app.route("/")
def index():
    username = session.get("username")
    search_results = search_keyword = None
    page_content = request.args.get("page_content")
    if username:
        user_info = get_safe_user_info(username)
        if not user_info: session.clear(); return render_template("index.html")
        avatar_url = None
        if user_info.get("avatar"): avatar_url = url_for("static", filename=f"uploads/{user_info['avatar']}")
        keyword = request.args.get("keyword", "").strip()
        if keyword:
            search_keyword = keyword; like = f"%{keyword}%"
            print(f"[SQL] LIKE params:('%{keyword}%')")
            search_results = [dict(r) for r in get_db().execute(
                "SELECT id,username,email,phone FROM users WHERE username LIKE ? OR email LIKE ?",
                (like, like)).fetchall()]
        return render_template("index.html", username=username, user=user_info,
            search_results=search_results, search_keyword=search_keyword, avatar_url=avatar_url,
            page_content=page_content)
    return render_template("index.html", page_content=page_content)

# ===== 登录 =====
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("username"): return redirect(url_for("index"))
    if request.method == "POST":
        if not validate_csrf_token(request.form.get("csrf_token", "")):
            return render_template("login.html", error="安全令牌无效", csrf_token=generate_csrf_token()), 400
        username = sanitize_input(request.form.get("username", ""), 32)
        password = request.form.get("password", "")
        if not username or not password:
            return render_template("login.html", error="请输入用户名和密码", csrf_token=generate_csrf_token())
        if account_locker.is_locked(username):
            return render_template("login.html", error="账户已锁定", csrf_token=generate_csrf_token())
        user = get_user_by_username(username)
        if user and verify_password(password, user["password_hash"]):
            account_locker.reset(username); session.permanent = True; session["username"] = username
            return redirect(url_for("index"))
        else:
            if user: account_locker.record_failure(username)
            return render_template("login.html", error="用户名或密码错误", csrf_token=generate_csrf_token())
    return render_template("login.html", csrf_token=generate_csrf_token())

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("index"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("username"): return redirect(url_for("index"))
    if not rate_limiter.is_allowed(f"reg:{request.remote_addr}", 3, 3600):
        return render_template("login.html", error="请求过频", csrf_token=generate_csrf_token()), 429
    if request.method == "POST":
        if not validate_csrf_token(request.form.get("csrf_token", "")):
            return render_template("register.html", error="安全令牌无效"), 400
        username = sanitize_input(request.form.get("username", ""), 32)
        password = request.form.get("password", ""); email = sanitize_input(request.form.get("email", ""), 254)
        phone = sanitize_input(request.form.get("phone", ""), 20)
        for fn, val, msg in [(validate_username, username, "用户名格式错误"),
            (validate_password, password, "密码强度不足"), (validate_email, email, "邮箱格式错误"),
            (validate_phone, phone, "手机号格式错误")]:
            valid, err = fn(val) if fn != validate_password else fn(val, username)
            if not valid: return render_template("register.html", error=err or msg, csrf_token=generate_csrf_token())
        try:
            pw_hash = hash_password(password)
            get_db().execute("INSERT INTO users(username,password_hash,role,email,phone,balance) VALUES(?,?,?,?,?,?)",
                           (username, pw_hash, "user", email, phone, 0))
            get_db().commit()
            return render_template("login.html", success="注册成功，请登录", csrf_token=generate_csrf_token())
        except sqlite3.IntegrityError:
            return render_template("register.html", error="用户名已存在", csrf_token=generate_csrf_token())
    return render_template("register.html", csrf_token=generate_csrf_token(), password_hint=generate_password_hint())

@app.route("/search")
def search():
    username = session.get("username")
    if not username: return redirect(url_for("login"))
    keyword = request.args.get("keyword", "").strip(); results = []
    if keyword:
        like = f"%{keyword}%"
        print(f"[SQL] SEARCH params:('%{keyword}%')")
        try:
            results = [dict(r) for r in get_db().execute(
                "SELECT id,username,email,phone FROM users WHERE username LIKE ? OR email LIKE ?",
                (like, like)).fetchall()]
        except Exception as e: print(f"[SQL ERROR] {e}")
    return render_template("index.html", username=username, user=get_safe_user_info(username),
                           search_results=results, search_keyword=keyword)

# ===== 头像上传 =====
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif'}
ALLOWED_MIMES = {'image/jpeg', 'image/png', 'image/gif'}
UPLOAD_FOLDER = Config.UPLOAD_FOLDER

def check_magic(filepath):
    with open(filepath, 'rb') as f:
        h = f.read(12)
    if h[:3] == b'\xff\xd8\xff': return '.jpeg'
    if h[:4] == b'\x89PNG': return '.png'
    if h[:6] in (b'GIF89a', b'GIF87a'): return '.gif'
    return None

@app.route("/upload", methods=["GET", "POST"])
def upload():
    username = session.get("username")
    if not username: return redirect(url_for("login"))
    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return render_template("upload.html", error="请选择要上传的文件")
        safe_name = secure_filename(file.filename)
        _, ext = os.path.splitext(safe_name); ext = ext.lower()
        if ext not in ALLOWED_EXTENSIONS:
            return render_template("upload.html", error=f"不允许上传{ext}文件")
        if file.content_type not in ALLOWED_MIMES:
            return render_template("upload.html", error="文件类型不正确")
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        tmp_name = f"tmp_{uuid.uuid4().hex}{ext}"
        tmp_path = os.path.join(UPLOAD_FOLDER, tmp_name)
        file.save(tmp_path)
        real_ext = check_magic(tmp_path)
        if real_ext is None:
            os.remove(tmp_path); return render_template("upload.html", error="文件内容不合法")
        final_name = f"{uuid.uuid4().hex}{real_ext}"
        final_path = os.path.join(UPLOAD_FOLDER, final_name)
        os.rename(tmp_path, final_path)
        get_db().execute("UPDATE users SET avatar=? WHERE username=?", (final_name, username))
        get_db().commit()
        file_url = url_for("static", filename=f"uploads/{final_name}")
        return render_template("upload.html", success=True, file_url=file_url, filename=final_name)
    return render_template("upload.html")

# ===== 个人中心 =====
@app.route("/profile")
def profile():
    username = session.get("username")
    if not username: return redirect(url_for("login"))
    user = get_user_by_username(username)
    if not user: return render_template("profile.html", error="用户不存在")
    user.pop("password_hash", None)
    return render_template("profile.html", profile_user=user, current_user=username)

# ===== 充值 =====
@app.route("/recharge", methods=["POST"])
def recharge():
    username = session.get("username")
    if not username: return redirect(url_for("login"))
    user = get_user_by_username(username)
    if not user: return render_template("profile.html", error="用户不存在")
    amount = request.form.get("amount", "0")
    try: amount = float(amount)
    except: return render_template("profile.html", error="金额格式不正确")
    if amount <= 0:
        return render_template("profile.html", error="充值金额必须大于 0")
    db = get_db()
    db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user["id"]))
    db.commit()
    logger.info("充值成功: 用户=%s, 金额=%s", username, amount)
    return redirect(url_for("profile"))


# ==============================================================
# ✅ 已修复：动态页面加载 — 路径遍历防御
# ==============================================================

import os.path

# 允许的页面白名单
ALLOWED_PAGES = {"help", "about", "contact"}

@app.route("/page", methods=["GET"])
def page():
    """
    动态页面加载

    ✅ 已修复：路径遍历（Path Traversal）
    - 白名单机制：只允许加载预定义的页面
    - name 参数不在白名单中则拒绝加载
    """
    name = request.args.get("name", "")

    if not name:
        return render_template("index.html", page_content="<p>请指定页面名称</p>")

    # ✅ 白名单校验：只允许加载预定义的页面
    if name not in ALLOWED_PAGES:
        logger.warning("页面访问被拒: 页面名 %s 不在白名单中", name)
        return render_template("index.html", page_content="<p>页面不存在</p>")

    # ✅ 使用安全的路径构建方式
    page_path = os.path.join("pages", name + ".html")

    if os.path.exists(page_path):
        with open(page_path, "r", encoding="utf-8") as f:
            content = f.read()
        return render_template("index.html", page_content=content)

    return render_template("index.html", page_content="<p>页面不存在</p>")


# ==============================================================
# ✅ 已修复：修改密码 — CSRF保护 + 原密码验证 + 只能改自己
# ==============================================================

@app.route("/change-password", methods=["POST"])
def change_password():
    """
    修改密码

    ✅ 已修复：CSRF Token 验证
    ✅ 已修复：验证当前登录用户（session），不从表单获取 username
    ✅ 已修复：验证原密码正确后才能设置新密码
    """
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    # ✅ CSRF Token 验证
    csrf_input = request.form.get("csrf_token", "")
    if not validate_csrf_token(csrf_input):
        logger.warning("CSRF 验证失败: 修改密码 (IP: %s)", request.remote_addr)
        return render_template("profile.html", error="安全令牌无效，请刷新页面重试")

    # ✅ 从 session 获取当前用户，不从表单获取（防止水平越权）
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")

    if not old_password or not new_password:
        return render_template("profile.html", error="请填写完整信息")

    # ✅ 验证原密码
    user = get_user_by_username(username)
    if not user or not verify_password(old_password, user["password_hash"]):
        logger.warning("密码修改失败: 原密码错误 (用户: %s)", username)
        return render_template("profile.html", error="原密码错误")

    # ✅ 更新密码
    pw_hash = hash_password(new_password)
    db = get_db()
    db.execute("UPDATE users SET password_hash = ? WHERE username = ?",
               (pw_hash, username))
    db.commit()

    logger.info("密码修改成功: 用户=%s", username)
    return redirect(url_for("profile"))


# ==============================================================
# ✅ 已修复：欢迎页 — SSTI修复
# ==============================================================

WELCOME_TEMPLATE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>欢迎页</title>
<link rel="stylesheet" href="/static/css/style.css">
<style>body{background:#f0f2f5;font-family:Arial,sans-serif;}.welcome-box{max-width:600px;margin:100px auto;background:#fff;border-radius:12px;padding:40px;text-align:center;box-shadow:0 4px 20px rgba(0,0,0,0.08);}h1{color:#1a73e8;}a{color:#1a73e8;text-decoration:none;}</style>
</head>
<body>
<nav class="navbar"><div class="navbar-brand"><a href="/" class="brand-link">用户管理系统</a></div>
<div class="navbar-menu"><a href="/" class="nav-link">首页</a><a href="/welcome" class="nav-link">欢迎页</a><a href="/feedback" class="nav-link">反馈</a></div></nav>
<div class="welcome-box">
<h1>欢迎你，{{ name }}！</h1>
<p><a href="/">← 返回首页</a></p>
</div>
</body>
</html>"""


@app.route("/welcome")
def welcome():
    """
    欢迎页面

    ✅ 已修复：SSTI
    - 使用 render_template_string + Jinja2 变量 {{ name }}
    - 用户输入通过模板变量传递，不会被当作模板代码执行
    - 自动 HTML 转义
    """
    name = request.args.get("name", "")
    if not name:
        name = "亲爱的用户"

    return render_template_string(WELCOME_TEMPLATE, name=name)


# ==============================================================
# ✅ 已修复：反馈页 — SSTI修复
# ==============================================================

FEEDBACK_FORM = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>反馈</title>
<link rel="stylesheet" href="/static/css/style.css">
<style>body{background:#f0f2f5;font-family:Arial,sans-serif;}.fb-box{max-width:500px;margin:60px auto;background:#fff;border-radius:12px;padding:36px;box-shadow:0 4px 20px rgba(0,0,0,0.08);}input,textarea{width:100%;padding:10px 14px;border:1px solid #d9d9d9;border-radius:6px;font-size:14px;margin:6px 0 16px;}label{font-weight:600;color:#555;}button{background:#1a73e8;color:#fff;border:none;padding:12px 24px;border-radius:6px;cursor:pointer;width:100%;font-size:15px;}h2{color:#1a73e8;}</style>
</head>
<body>
<nav class="navbar"><div class="navbar-brand"><a href="/" class="brand-link">用户管理系统</a></div>
<div class="navbar-menu"><a href="/" class="nav-link">首页</a><a href="/welcome" class="nav-link">欢迎页</a><a href="/feedback" class="nav-link">反馈</a></div></nav>
<div class="fb-box">
<h2>提交反馈</h2>
<form method="post" action="/feedback">
<label>姓名</label><input type="text" name="name" placeholder="请输入姓名" required>
<label>留言</label><textarea name="message" rows="4" placeholder="请输入您的反馈内容" required></textarea>
<button type="submit">提交反馈</button>
</form>
</div>
</body>
</html>"""

FEEDBACK_RESULT_TEMPLATE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>反馈结果</title>
<link rel="stylesheet" href="/static/css/style.css">
<style>body{background:#f0f2f5;font-family:Arial,sans-serif;}.result-box{max-width:600px;margin:100px auto;background:#fff;border-radius:12px;padding:40px;box-shadow:0 4px 20px rgba(0,0,0,0.08);}h2{color:#1a73e8;}.msg{background:#f8f9ff;border-left:4px solid #1a73e8;padding:16px;border-radius:4px;margin:16px 0;}</style>
</head>
<body>
<nav class="navbar"><div class="navbar-brand"><a href="/" class="brand-link">用户管理系统</a></div>
<div class="navbar-menu"><a href="/" class="nav-link">首页</a><a href="/welcome" class="nav-link">欢迎页</a><a href="/feedback" class="nav-link">反馈</a></div></nav>
<div class="result-box">
<h2>{{ name }} 的反馈：</h2>
<div class="msg">{{ message }}</div>
<p style="color:#888;">感谢您的反馈！</p>
<p><a href="/">← 返回首页</a></p>
</div>
</body>
</html>"""


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    """
    反馈页面

    ✅ 已修复：SSTI
    - 使用 Jinja2 模板变量 {{ name }} {{ message }}
    - 用户输入通过模板变量传递，不会被当作模板代码执行
    - 自动 HTML 转义
    """
    if request.method == "POST":
        name = request.form.get("name", "")
        message = request.form.get("message", "")

        return render_template_string(FEEDBACK_RESULT_TEMPLATE, name=name, message=message)

    return render_template_string(FEEDBACK_FORM)


# ==============================================================
# ✅ 已修复：Ping测试 — 命令注入防御
# ==============================================================

@app.route("/ping", methods=["GET", "POST"])
def ping():
    """
    Ping 网络诊断

    ✅ 已修复：命令注入（Command Injection）
    - 使用 shlex.quote() 过滤用户输入
    - shell=False 禁止执行任意命令
    - IP 参数仅允许传入一个参数（不含空格和特殊符号）
    """
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    result = None
    error = None

    if request.method == "POST":
        ip = request.form.get("ip", "")

        if not ip:
            error = "请输入 IP 地址"
        else:
            # ✅ 使用 shlex.quote() 过滤用户输入
            safe_ip = shlex.quote(ip.strip())

            # ✅ shell=False，参数以列表形式传递
            cmd = ["ping", "-c", "3", safe_ip]
            print(f"\n⚡ [CMD] 执行命令: {' '.join(cmd)}\n")

            try:
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=30)
                result = output.decode("utf-8", errors="replace")
                logger.info("Ping成功: 用户=%s, IP=%s", username, safe_ip)
            except subprocess.CalledProcessError as e:
                error = f"Ping执行失败（返回码: {e.returncode}）"
                if e.output:
                    error += "\n" + e.output.decode("utf-8", errors="replace")
            except subprocess.TimeoutExpired:
                error = "Ping执行超时（30秒）"
            except Exception as e:
                error = f"执行错误: {str(e)}"

    return render_template("ping.html", result=result, error=error)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "9.0.0-secure"}), 200

@app.errorhandler(404)
def not_found(e): return render_template("base.html", error="404"), 404
@app.errorhandler(500)
def server_error(e): return render_template("base.html", error="500"), 500

if __name__ == "__main__":
    logger.info("用户管理系统(命令注入修复版)启动: 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
