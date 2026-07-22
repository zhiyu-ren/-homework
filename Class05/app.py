#!/usr/bin/env python3
"""
用户信息管理系统 - 业务逻辑漏洞修复版
===================================
基于 Class05，修复个人中心和充值功能中的安全漏洞

修复说明：
  1. ✅ /profile — 水平越权修复：只能查看自己的资料（从session获取user_id）
  2. ✅ /recharge — 负值交易修复：校验 amount > 0，只能给自己充值
"""
import os, sys, logging, sqlite3, hmac, secrets, time, uuid
from datetime import timedelta
from collections import defaultdict
from flask import Flask, render_template, request, redirect, session, url_for, g, jsonify
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
            search_results=search_results, search_keyword=search_keyword, avatar_url=avatar_url)
    return render_template("index.html")

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

# ===== 注册 =====
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

# ===== 搜索 =====
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
            logger.warning("上传被拒:扩展名%s", ext)
            return render_template("upload.html", error=f"不允许上传{ext}文件")
        if file.content_type not in ALLOWED_MIMES:
            logger.warning("上传被拒:MIME%s", file.content_type)
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
        logger.info("头像上传成功:%s", final_name)
        return render_template("upload.html", success=True, file_url=file_url, filename=final_name)
    return render_template("upload.html")


# ==============================================================
# ✅ 已修复：个人中心 — 仅查看自己的资料
# ==============================================================

@app.route("/profile")
def profile():
    """
    个人中心页面

    ✅ 已修复：水平越权（IDOR）
    - user_id 从当前 session 中获取，而非 URL 参数
    - 用户只能查看自己的资料
    - 传入其他用户的 ID 无法越权查看
    """
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    # ✅ 从 session 获取当前登录用户的用户名，再查询 id
    user = get_user_by_username(username)
    if not user:
        return render_template("profile.html", error="用户不存在")
    user_id = user["id"]

    # ✅ 直接查询当前用户的完整信息
    user = get_user_by_id(user_id)
    if not user:
        return render_template("profile.html", error="用户不存在")

    # 隐藏敏感字段
    user.pop("password_hash", None)

    logger.info("个人中心访问: 用户=%s, ID=%s", username, user_id)
    return render_template("profile.html", profile_user=user, current_user=username)


# ==============================================================
# ✅ 已修复：充值 — 正数金额校验 + 只能给自己充值
# ==============================================================

@app.route("/recharge", methods=["POST"])
def recharge():
    """
    充值功能

    ✅ 已修复：负值交易
    - 校验 amount > 0，传入负数会拒绝
    - user_id 从 session 获取，只能给自己充值
    """
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    # ✅ 从 session 获取当前用户
    user = get_user_by_username(username)
    if not user:
        return render_template("profile.html", error="用户不存在")

    amount = request.form.get("amount", "0")

    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return render_template("profile.html", error="金额格式不正确")

    # ✅ 校验金额必须大于 0
    if amount <= 0:
        logger.warning("充值被拒: 金额无效 %s (用户: %s)", amount, username)
        return render_template("profile.html", error="充值金额必须大于 0")

    # ✅ 只能给自己充值（从 session 获取 user_id）
    db = get_db()
    db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user["id"]))
    db.commit()

    logger.info("充值成功: 用户=%s, 金额=%s", username, amount)

    # 充值成功后跳转到个人中心
    return redirect(url_for("profile"))


@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "5.0.0-secure"}), 200

@app.errorhandler(404)
def not_found(e): return render_template("base.html", error="404"), 404
@app.errorhandler(500)
def server_error(e): return render_template("base.html", error="500"), 500

if __name__ == "__main__":
    logger.info("用户管理系统(业务逻辑漏洞修复版)启动: 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
