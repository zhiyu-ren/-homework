"""
认证工具模块
=============
密码哈希、账户锁定、登录审计
"""

import time
import logging
from threading import Lock
from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger("auth")

# ---------- 密码哈希 ----------

def hash_password(password: str) -> str:
    """
    使用 Werkzeug 的 PBKDF2-SHA256 对密码进行哈希

    参数:
        password: 明文密码

    返回:
        哈希后的密码字符串（含盐值）
    """
    return generate_password_hash(password, method="pbkdf2:sha256:600000")


def verify_password(password: str, password_hash: str) -> bool:
    """
    验证明文密码与哈希是否匹配

    参数:
        password: 待验证的明文密码
        password_hash: 存储的哈希值

    返回:
        是否匹配
    """
    return check_password_hash(password_hash, password)


# ---------- 账户锁定机制 ----------

class AccountLocker:
    """
    账户锁定管理器

    配置:
        MAX_ATTEMPTS: 最大失败尝试次数（默认 5）
        LOCKOUT_DURATION: 锁定持续时间（秒，默认 900 = 15 分钟）
        WINDOW_DURATION: 统计窗口（秒，默认 300 = 5 分钟）
    """

    def __init__(self, max_attempts=5, lockout_duration=900, window_duration=300):
        self._max_attempts = max_attempts
        self._lockout_duration = lockout_duration
        self._window_duration = window_duration
        self._attempts: dict[str, list[float]] = {}
        self._lockouts: dict[str, float] = {}
        self._lock = Lock()

    def record_failure(self, username: str):
        """记录一次失败登录"""
        now = time.time()
        with self._lock:
            if username not in self._attempts:
                self._attempts[username] = []
            # 清理窗口外的旧记录
            self._attempts[username] = [
                t for t in self._attempts[username]
                if now - t < self._window_duration
            ]
            self._attempts[username].append(now)

            # 检查是否达到锁定阈值
            if len(self._attempts[username]) >= self._max_attempts:
                self._lockouts[username] = now
                logger.warning("账户已锁定: %s (尝试 %d 次)", username, self._max_attempts)

    def is_locked(self, username: str) -> bool:
        """检查账户是否被锁定"""
        now = time.time()
        with self._lock:
            if username in self._lockouts:
                elapsed = now - self._lockouts[username]
                if elapsed < self._lockout_duration:
                    remaining = int(self._lockout_duration - elapsed)
                    logger.info("账户仍被锁定: %s (剩余 %d 秒)", username, remaining)
                    return True
                else:
                    # 锁定时间已过，移除锁定并清空记录
                    del self._lockouts[username]
                    self._attempts.pop(username, None)
                    logger.info("账户已解锁: %s", username)
            return False

    def reset(self, username: str):
        """登录成功后重置失败计数"""
        with self._lock:
            self._attempts.pop(username, None)
            self._lockouts.pop(username, None)

    def get_remaining_attempts(self, username: str) -> int:
        """获取剩余尝试次数"""
        now = time.time()
        with self._lock:
            if username not in self._attempts:
                return self._max_attempts
            recent = [t for t in self._attempts[username] if now - t < self._window_duration]
            return max(0, self._max_attempts - len(recent))


# 全局单例
account_locker = AccountLocker()
