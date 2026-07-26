"""
密码策略模块
=============
强密码策略强制实施

策略规则：
  - 最小长度 12 字符
  - 包含大写字母
  - 包含小写字母
  - 包含数字
  - 包含特殊字符
  - 不与用户名相同
  - 不在常见弱密码列表中
"""

import re

# 常见弱密码黑名单
WEAK_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "abc123",
    "admin123", "123456789", "letmein", "welcome", "monkey",
    "password123", "1234567890", "admin123456", "passw0rd",
    "p@ssword", "P@ssw0rd", "hello123", "iloveyou",
    "admin", "root", "test123", "123qwe", "qwe123",
}


def validate_password(password: str, username: str = "") -> tuple[bool, str]:
    """
    验证密码强度

    参数:
        password: 待验证密码
        username: 用户名（用于检查密码是否包含用户名）

    返回:
        (是否通过, 错误信息)
    """
    # 检查不为空
    if not password:
        return False, "密码不能为空"

    # 检查长度 >= 12
    if len(password) < 12:
        return False, "密码长度至少为 12 个字符"

    # 检查是否包含大写字母
    if not re.search(r"[A-Z]", password):
        return False, "密码必须包含至少一个大写字母"

    # 检查是否包含小写字母
    if not re.search(r"[a-z]", password):
        return False, "密码必须包含至少一个小写字母"

    # 检查是否包含数字
    if not re.search(r"\d", password):
        return False, "密码必须包含至少一个数字"

    # 检查是否包含特殊字符
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;'/`~]", password):
        return False, "密码必须包含至少一个特殊字符"

    # 检查是否包含用户名（忽略大小写）
    if username and username.lower() in password.lower():
        return False, "密码不能包含用户名"

    # 检查弱密码黑名单
    if password.lower() in WEAK_PASSWORDS:
        return False, "该密码过于常见，请使用更复杂的密码"

    return True, ""


def generate_password_hint() -> str:
    """生成密码策略提示信息"""
    return (
        "密码必须满足以下条件：\n"
        "• 至少 12 个字符\n"
        "• 包含大写字母 (A-Z)\n"
        "• 包含小写字母 (a-z)\n"
        "• 包含数字 (0-9)\n"
        "• 包含特殊字符 (!@#$%^&*等)\n"
        "• 不能包含用户名\n"
        "• 不能是常见弱密码"
    )
