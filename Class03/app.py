#!/usr/bin/env python3
"""
用户信息管理系统 - SQL注入修复版
=================================
基于 Class02 安全加固版，新增注册和搜索功能并修复SQL注入

修复内容：
  1. 注册功能：参数化查询替代 f-string SQL 拼接 ✅
  2. 搜索功能：参数化查询替代 f-string SQL 拼接 ✅
  3. 新增CSRF保护、输入验证、强密码策略 ✅
"""

import os
import sys
import logging
from datetime import timedelta

from flask import (
    Flask, render_template, request, redirect,
    session, url_for, g, jsonify, abort
)

from config import Config
from utils.auth import hash_password, verify_password, account_locker
from utils.password_policy import validate_password, generate_password_hint
from utils.validators import (
    validate_username, validate_email, validate_phone, sanitize_input
)

# ==============================================================
# 应用初始化
# ==============================================================

app = Flask(__name__)
app.config.from_object(Config)

# Session 过期时间
app.permanent_session_lifetime = timedelta(seconds=Config.PERMANENT_SESSION_LIFETIME)

# ---------- 安全审计日志配置 ----------
os.makedirs(os.path.dirname(Config.LOG_FILE) or ".", exist_ok=True)
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(Config.LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger("security")


# ==============================================================
# 安全响应头中间件
# ==============================================================

@app.after_request
def add_security_headers(response):
    """为所有响应添加安全响应头"""
    for header, value in Config.SECURITY_HEADERS.items():
        response.headers[header] = value
    return response


# ==============================================================
# 速率限制（简化实现，不依赖 Flask-Limiter）
# ==============================================================

from collections import defaultdict
import time

class RateLimiter:
    """简易内存速率限制器"""
    def __init__(self):
        self._records: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str, max_count: int, window_sec: int) -> bool:
        now = time.time()
        records = self._records[key]
        self._records[key] = [t for t in records if now - t < window_sec]
        if len(self._records[key]) >= max_count:
            return False
        self._records[key].append(now)
        return True

rate_limiter = RateLimiter()


# ==============================================================
# CSRF 保护
# ==============================================================

import hmac
import secrets

def generate_csrf_token() -> str:
    if "_csrf_token" not in session:
        token = secrets.token_hex(32)
        session["_csrf_token"] = token
    return session["_csrf_token"]

def validate_csrf_token(token: str) -> bool:
    stored = session.get("_csrf_token")
    if not stored or not token:
        return False
    return hmac.compare_digest(stored, token)

app.jinja_env.globals["csrf_token"] = generate_csrf_token


# ==============================================================
# 用户数据库（SQLite）
# ==============================================================

import sqlite3

DATABASE = Config.DB_PATH


def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DATABASE) or ".", exist_ok=True)
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """初始化数据库表结构"""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.commit()


def seed_default_users():
    """插入默认用户（仅首次运行时）"""
    db = get_db()
    existing = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if existing > 0:
        return

    users = [
        ("admin", "Admin@2025Secure!", "admin", "admin@example.com", "13800138000", 99999),
        ("alice", "Alice@2025Secure!", "user", "alice@example.com", "13900139001", 100),
    ]

    for username, password, role, email, phone, balance in users:
        pw_hash = hash_password(password)
        db.execute(
            "INSERT INTO users (username, password_hash, role, email, phone, balance) VALUES (?, ?, ?, ?, ?, ?)",
            (username, pw_hash, role, email, phone, balance),
        )
        logger.info("初始用户已创建: %s (角色: %s)", username, role)

    db.commit()


# ---------- 初始化数据库 ----------
with app.app_context():
    init_db()
    seed_default_users()


# ==============================================================
# 用户数据访问层（登录用安全版）
# ==============================================================

def get_user_by_username(username: str) -> dict | None:
    """通过用户名获取用户信息"""
    db = get_db()
    row = db.execute(
        "SELECT id, username, password_hash, role, email, phone, balance, created_at FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if row:
        return dict(row)
    return None


def get_safe_user_info(username: str) -> dict | None:
    """获取安全可显示的用户信息（不含敏感字段）"""
    user = get_user_by_username(username)
    if user:
        user.pop("password_hash", None)
        user.pop("id", None)
        return user
    return None


# ==============================================================
# 路由 - 首页
# ==============================================================

@app.route("/")
def index():
    """首页：显示当前登录用户信息 + 搜索功能"""
    username = session.get("username")
    search_results = None
    search_keyword = None

    if username:
        user_info = get_safe_user_info(username)
        if user_info is None:
            session.clear()
            return render_template("index.html", username=None, user=None,
                                   search_results=None, search_keyword=None)

        # 处理搜索参数
        keyword = request.args.get("keyword", "").strip()
        if keyword:
            search_keyword = keyword
                # ✅ 已修复：使用参数化查询（?占位符）
            like = f"%{keyword}%"
            sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
            print(f"\n🔍 [SQL] {sql} 参数:('%{keyword}%')\n")
            db = get_db()
            cur = db.execute(sql, (like, like))
            rows = cur.fetchall()
            search_results = [dict(r) for r in rows]

        return render_template("index.html", username=username, user=user_info,
                               search_results=search_results, search_keyword=search_keyword)

    return render_template("index.html", username=None, user=None,
                           search_results=None, search_keyword=None)


# ==============================================================
# 路由 - 登录（保持安全加固版不变）
# ==============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    """登录页面 - 保持原有安全加固版逻辑"""
    if session.get("username"):
        return redirect(url_for("index"))

    if request.method == "POST":
        # CSRF 验证
        csrf_input = request.form.get("csrf_token", "")
        if not validate_csrf_token(csrf_input):
            logger.warning("CSRF 验证失败 (IP: %s)", request.remote_addr)
            return render_template("login.html", error="安全令牌无效，请刷新页面重试", csrf_token=generate_csrf_token()), 400

        username = sanitize_input(request.form.get("username", ""), 32)
        password = request.form.get("password", "")

        if not username or not password:
            return render_template("login.html", error="请输入用户名和密码", csrf_token=generate_csrf_token())

        if account_locker.is_locked(username):
            return render_template("login.html", error="账户已被临时锁定，请 15 分钟后重试", csrf_token=generate_csrf_token())

        user = get_user_by_username(username)

        if user and verify_password(password, user["password_hash"]):
            account_locker.reset(username)
            session.permanent = True
            session["username"] = username
            logger.info("登录成功: %s (IP: %s)", username, request.remote_addr)
            return redirect(url_for("index"))
        else:
            if user:
                account_locker.record_failure(username)
            return render_template("login.html", error="用户名或密码错误", csrf_token=generate_csrf_token())

    return render_template("login.html", csrf_token=generate_csrf_token())


# ==============================================================
# 路由 - 登出
# ==============================================================

@app.route("/logout")
def logout():
    username = session.get("username", "未知")
    session.clear()
    logger.info("用户登出: %s (IP: %s)", username, request.remote_addr)
    return redirect(url_for("index"))


# ==============================================================
# 路由 - 注册（✅ 已修复：参数化查询防注入）
# ==============================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    """
    注册页面 - 安全修复版

    ✅ 已修复：参数化查询替代 f-string SQL 拼接
    ✅ 已修复：强密码策略 + CSRF + 输入验证
    """
    if session.get("username"):
        return redirect(url_for("index"))

    if request.method == "POST":
        # CSRF 验证
        if not validate_csrf_token(request.form.get("csrf_token", "")):
            return render_template("register.html", error="安全令牌无效"), 400

        username = sanitize_input(request.form.get("username", ""), 32)
        password = request.form.get("password", "")
        email = sanitize_input(request.form.get("email", ""), 254)
        phone = sanitize_input(request.form.get("phone", ""), 20)

        # 输入验证
        valid, err = validate_username(username)
        if not valid: return render_template("register.html", error=err, csrf_token=generate_csrf_token())
        valid, err = validate_password(password, username)
        if not valid: return render_template("register.html", error=err, csrf_token=generate_csrf_token())
        valid, err = validate_email(email)
        if not valid: return render_template("register.html", error=err, csrf_token=generate_csrf_token())
        valid, err = validate_phone(phone)
        if not valid: return render_template("register.html", error=err, csrf_token=generate_csrf_token())

        # ✅ 已修复：参数化查询
        pw_hash = hash_password(password)
        sql = "INSERT INTO users (username, password_hash, role, email, phone, balance) VALUES (?, ?, ?, ?, ?, ?)"
        print(f"\n📝 [SQL] {sql} 参数:({username}, {email})\n")

        try:
            db = get_db()
            db.execute(sql, (username, pw_hash, 'user', email, phone, 0))
            db.commit()
            logger.info("用户注册成功: %s (IP: %s)", username, request.remote_addr)
            return render_template("login.html", success="注册成功，请登录", csrf_token=generate_csrf_token())
        except sqlite3.IntegrityError:
            return render_template("register.html", error="用户名已存在", csrf_token=generate_csrf_token())
        except Exception as e:
            logger.error("注册失败: %s", str(e))
            return render_template("register.html", error=f"注册失败", csrf_token=generate_csrf_token())

    return render_template("register.html", csrf_token=generate_csrf_token(), password_hint=generate_password_hint())


# ==============================================================
# 路由 - 搜索（✅ 已修复：参数化查询防注入）
# ==============================================================

@app.route("/search")
def search():
    """
    搜索页面 - 安全修复版

    ✅ 已修复：参数化查询替代 f-string SQL 拼接
    """
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    keyword = request.args.get("keyword", "").strip()
    results = []

    if keyword:
        # ✅ 已修复：使用参数化查询（?占位符）
        like = f"%{keyword}%"
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        print(f"\n🔍 [SQL] {sql} 参数:('%{keyword}%')\n")

        try:
            db = get_db()
            cur = db.execute(sql, (like, like))
            rows = cur.fetchall()
            results = [dict(r) for r in rows]
        except Exception as e:
            print(f"❌ [SQL ERROR] {e}")

    user_info = get_safe_user_info(username)
    return render_template("index.html", username=username, user=user_info,
                           search_results=results, search_keyword=keyword)


# ==============================================================
# 健康检查
# ==============================================================

@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "3.0.0-sqli"}), 200


# ==============================================================
# 错误处理
# ==============================================================

@app.errorhandler(404)
def not_found(e):
    return render_template("base.html", error="404 - 页面未找到"), 404

@app.errorhandler(500)
def server_error(e):
    logger.error("服务器内部错误: %s", str(e))
    return render_template("base.html", error="服务器内部错误，请稍后重试"), 500


# ==============================================================
# 启动入口
# ==============================================================

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("用户信息管理系统 - SQL注入修复版 启动")
    logger.info("监听地址: 0.0.0.0:5000")
    logger.info("测试账号: admin / Admin@2025Secure!, alice / Alice@2025Secure!")
    logger.info("=" * 60)

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=Config.DEBUG,
    )
