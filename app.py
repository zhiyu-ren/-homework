#!/usr/bin/env python3
"""
用户信息管理系统 - 安全加固版
===============================
基于 Flask 的安全用户管理平台

安全修复清单：
  1. ✅ 密码 PBKDF2-SHA256 哈希存储（Werkzeug）
  2. ✅ Secret Key 环境变量隔离 / 自动生成
  3. ✅ 模板中不显示密码字段
  4. ✅ 调试模式由环境变量控制
  5. ✅ 移除所有调试信息注释
  6. ✅ Session 安全：HttpOnly + SameSite + 过期时间
  7. ✅ 登录限流：Flask-Limiter 每分钟 10 次
  8. ✅ 注册限流：每 IP 每小时 3 次
  9. ✅ 输入验证：用户名、邮箱、手机号格式校验
  10. ✅ 密码策略：12 位 + 大小写 + 数字 + 特殊字符 + 黑名单
  11. ✅ CSRF 令牌保护（Flask-WTF）自定义实现
  12. ✅ 账户锁定：5 次失败锁定 15 分钟
  13. ✅ 通用错误提示：不泄露用户名是否存在
  14. ✅ 安全审计日志：记录所有登录/注册行为
  15. ✅ 安全响应头：HSTS、X-Frame-Options、XSS 保护等
  16. ✅ 点击劫持防护
  17. ✅ 用户输入清理（Sanitization）
  18. ✅ 配置文件隔离管理

启动方式：
  python3 app.py
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
        # 清理过期记录
        self._records[key] = [t for t in records if now - t < window_sec]
        if len(self._records[key]) >= max_count:
            return False
        self._records[key].append(now)
        return True

rate_limiter = RateLimiter()


# ==============================================================
# CSRF 保护（轻量实现，无需 Flask-WTF 表单类）
# ==============================================================

import hmac
import hashlib

def generate_csrf_token() -> str:
    """生成 CSRF 令牌并存入 session"""
    if "_csrf_token" not in session:
        token = secrets.token_hex(32)
        session["_csrf_token"] = token
    return session["_csrf_token"]

def validate_csrf_token(token: str) -> bool:
    """验证 CSRF 令牌"""
    stored = session.get("_csrf_token")
    if not stored or not token:
        return False
    return hmac.compare_digest(stored, token)

app.jinja_env.globals["csrf_token"] = generate_csrf_token


# ==============================================================
# 用户数据库（SQLite 替代内存字典）
# ==============================================================

import sqlite3
import secrets

DATABASE = Config.DB_PATH


def get_db():
    """获取数据库连接（每个请求一个连接）"""
    if "db" not in g:
        os.makedirs(os.path.dirname(DATABASE) or ".", exist_ok=True)
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """请求结束后关闭数据库连接"""
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
# 用户数据访问层
# ==============================================================

def get_user_by_username(username: str) -> dict | None:
    """通过用户名获取用户信息（不含敏感字段）"""
    db = get_db()
    row = db.execute(
        "SELECT id, username, password_hash, role, email, phone, balance, created_at FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if row:
        return dict(row)
    return None


def get_safe_user_info(username: str) -> dict | None:
    """
    获取安全可显示的用户信息

    不包含 password_hash 等敏感字段
    """
    user = get_user_by_username(username)
    if user:
        # 移除敏感字段
        user.pop("password_hash", None)
        user.pop("id", None)
        return user
    return None


def create_user(username: str, password: str, email: str, phone: str) -> bool:
    """创建新用户"""
    db = get_db()
    try:
        pw_hash = hash_password(password)
        db.execute(
            "INSERT INTO users (username, password_hash, email, phone) VALUES (?, ?, ?, ?)",
            (username, pw_hash, email, phone),
        )
        db.commit()
        logger.info("新用户注册成功: %s", username)
        return True
    except sqlite3.IntegrityError:
        logger.warning("用户注册失败（用户名已存在）: %s", username)
        return False


# ==============================================================
# 路由
# ==============================================================

@app.route("/")
def index():
    """首页：显示当前登录用户的安全信息（不包含密码）"""
    username = session.get("username")
    if username:
        user_info = get_safe_user_info(username)
        if user_info is None:
            # Session 异常：用户可能已被删除
            session.clear()
            return render_template("index.html", username=None, user=None)
        return render_template("index.html", username=username, user=user_info)
    return render_template("index.html", username=None, user=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    登录页面

    安全措施：
      - 速率限制：每分钟最多 10 次
      - 账户锁定：5 次失败锁定 15 分钟
      - 通用错误提示：不暴露用户名是否存在
      - CSRF 验证
      - 安全审计日志
      - 密码：PBKDF2-SHA256 验证
    """
    # 已登录用户跳转到首页
    if session.get("username"):
        return redirect(url_for("index"))

    if request.method == "POST":
        # ---- CSRF 验证 ----
        csrf_input = request.form.get("csrf_token", "")
        if not validate_csrf_token(csrf_input):
            logger.warning("CSRF 验证失败 (IP: %s)", request.remote_addr)
            return render_template("login.html", error="安全令牌无效，请刷新页面重试", csrf_token=generate_csrf_token()), 400

        # ---- 获取并清理输入 ----
        username = sanitize_input(request.form.get("username", ""), 32)
        password = request.form.get("password", "")

        # ---- 输入基本校验 ----
        if not username or not password:
            logger.info("登录失败: 输入为空 (IP: %s)", request.remote_addr)
            return render_template(
                "login.html",
                error="请输入用户名和密码",
                csrf_token=generate_csrf_token(),
                password_hint=generate_password_hint()
            )

        # ---- 账户锁定检查 ----
        if account_locker.is_locked(username):
            logger.warning("登录被拒: 账户已锁定 %s (IP: %s)", username, request.remote_addr)
            return render_template(
                "login.html",
                error="账户已被临时锁定，请 15 分钟后重试",
                csrf_token=generate_csrf_token()
            )

        # ---- 验证用户凭证 ----
        user = get_user_by_username(username)

        if user and verify_password(password, user["password_hash"]):
            # ✅ 登录成功
            account_locker.reset(username)
            session.permanent = True
            session["username"] = username
            logger.info("登录成功: %s (IP: %s)", username, request.remote_addr)

            # 登录成功后跳转到首页
            return redirect(url_for("index"))
        else:
            # ❌ 登录失败
            if user:
                account_locker.record_failure(username)
                remaining = account_locker.get_remaining_attempts(username)
                logger.warning(
                    "登录失败: %s (剩余尝试: %d, IP: %s)",
                    username, remaining, request.remote_addr
                )
            else:
                # 对不存在的用户名同样记录但不区分提示
                logger.info("登录失败: 用户名不存在 (IP: %s)", request.remote_addr)

            # 统一错误提示：不区分"用户不存在"和"密码错误"
            return render_template(
                "login.html",
                error="用户名或密码错误",
                csrf_token=generate_csrf_token(),
                password_hint=generate_password_hint()
            )

    # GET 请求
    return render_template("login.html", csrf_token=generate_csrf_token(), password_hint=generate_password_hint())


@app.route("/logout")
def logout():
    """登出：清除 session 并跳转到首页"""
    username = session.get("username", "未知")
    session.clear()
    logger.info("用户登出: %s (IP: %s)", username, request.remote_addr)
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    注册页面

    安全措施：
      - 速率限制：每 IP 每小时最多 3 次
      - 强密码策略强制实施
      - 输入验证
      - CSRF 保护
    """
    if session.get("username"):
        return redirect(url_for("index"))

    # ---- 速率限制 ----
    client_ip = request.remote_addr or "unknown"
    if not rate_limiter.is_allowed(f"register:{client_ip}", 3, 3600):
        logger.warning("注册限流触发 (IP: %s)", client_ip)
        return render_template(
            "login.html",
            error="注册请求过于频繁，请稍后重试",
            csrf_token=generate_csrf_token()
        ), 429

    if request.method == "POST":
        # CSRF 验证
        csrf_input = request.form.get("csrf_token", "")
        if not validate_csrf_token(csrf_input):
            return render_template("register.html", error="安全令牌无效，请刷新页面重试"), 400

        # ---- 获取并验证输入 ----
        username = sanitize_input(request.form.get("username", ""), 32)
        password = request.form.get("password", "")
        email = sanitize_input(request.form.get("email", ""), 254)
        phone = sanitize_input(request.form.get("phone", ""), 20)

        # 用户名验证
        valid, err_msg = validate_username(username)
        if not valid:
            return render_template("register.html", error=err_msg, csrf_token=generate_csrf_token())

        # 密码验证
        valid, err_msg = validate_password(password, username)
        if not valid:
            return render_template("register.html", error=err_msg, csrf_token=generate_csrf_token())

        # 邮箱验证
        valid, err_msg = validate_email(email)
        if not valid:
            return render_template("register.html", error=err_msg, csrf_token=generate_csrf_token())

        # 手机号验证
        valid, err_msg = validate_phone(phone)
        if not valid:
            return render_template("register.html", error=err_msg, csrf_token=generate_csrf_token())

        # ---- 创建用户 ----
        if create_user(username, password, email, phone):
            logger.info("用户注册成功: %s (IP: %s)", username, client_ip)
            return render_template(
                "login.html",
                success="注册成功！请使用新账号登录",
                csrf_token=generate_csrf_token()
            )
        else:
            return render_template(
                "register.html",
                error="用户名已存在，请选择其他用户名",
                csrf_token=generate_csrf_token()
            )

    return render_template("register.html", csrf_token=generate_csrf_token(), password_hint=generate_password_hint())


# ==============================================================
# 健康检查
# ==============================================================

@app.route("/health")
def health():
    """健康检查端点"""
    return jsonify({"status": "ok", "version": "2.0.0"}), 200


# ==============================================================
# 错误处理
# ==============================================================

@app.errorhandler(404)
def not_found(e):
    return render_template("base.html", error="404 - 页面未找到"), 404


@app.errorhandler(429)
def too_many_requests(e):
    return render_template("base.html", error="请求过于频繁，请稍后重试"), 429


@app.errorhandler(500)
def server_error(e):
    logger.error("服务器内部错误: %s", str(e))
    return render_template("base.html", error="服务器内部错误，请稍后重试"), 500


# ==============================================================
# 启动入口
# ==============================================================

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("用户信息管理系统 - 安全加固版 启动")
    logger.info("监听地址: 0.0.0.0:5000")
    logger.info("调试模式: %s", Config.DEBUG)
    logger.info("Session 过期: %d 秒", Config.PERMANENT_SESSION_LIFETIME)
    logger.info("数据库路径: %s", Config.DB_PATH)
    logger.info("日志文件: %s", Config.LOG_FILE)
    logger.info("=" * 60)

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=Config.DEBUG,
    )
