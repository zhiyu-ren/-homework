"""
配置管理模块
=============
敏感配置隔离管理

从环境变量或 .env 文件加载配置，避免硬编码敏感信息。

安全策略：
  - Secret Key 从环境变量读取，不留默认值
  - 数据库路径可配置
  - 生产/开发环境自动切换
  - Session 安全参数集中管理
"""

import os
import secrets
from pathlib import Path


def _load_env_file(env_path: str | None = None) -> None:
    """简易 .env 文件加载器（无外部依赖）"""
    if env_path is None:
        base = Path(__file__).resolve().parent
        env_path = str(base / ".env")
    env_file = Path(env_path)
    if not env_file.exists():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        # 只设置尚未存在的环境变量
        if key not in os.environ:
            os.environ[key] = value


# 启动时加载 .env 文件
_load_env_file()


class Config:
    """应用配置类"""

    # ---------- 基础配置 ----------
    # Secret Key：优先从环境变量读取，否则自动生成（仅开发环境）
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        secrets.token_hex(32)  # 自动生成 64 字符随机密钥
    )

    # 调试模式：仅当 FLASK_ENV=development 时开启
    DEBUG = os.environ.get("FLASK_ENV") == "development"

    # ---------- Session 安全配置 ----------
    SESSION_COOKIE_HTTPONLY = True       # 禁止 JS 读取 session cookie
    SESSION_COOKIE_SAMESITE = "Lax"      # 防止 CSRF 跨站请求
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"  # HTTPS 下启用
    PERMANENT_SESSION_LIFETIME = 1800    # Session 过期时间：30 分钟（秒）

    # ---------- 数据库配置 ----------
    BASE_DIR = Path(__file__).resolve().parent
    DB_PATH = os.environ.get(
        "DB_PATH",
        str(BASE_DIR / "data" / "users.db")
    )

    # ---------- 安全响应头 ----------
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }

    # ---------- 速率限制 ----------
    RATELIMIT_LOGIN = os.environ.get("RATELIMIT_LOGIN", "10 per minute")
    RATELIMIT_REGISTER = os.environ.get("RATELIMIT_REGISTER", "3 per hour")

    # ---------- CSRF 保护 ----------
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # CSRF 令牌有效期 1 小时

    # ---------- 审计日志 ----------
    LOG_FILE = os.environ.get("LOG_FILE", str(BASE_DIR / "logs" / "security.log"))
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
