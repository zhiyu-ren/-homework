"""
输入验证模块
=============
用户输入校验和清理
"""

import re


def validate_username(username: str) -> tuple[bool, str]:
    """
    验证用户名格式

    规则：
      - 3-32 个字符
      - 只能包含字母、数字、下划线、连字符
      - 不能以连字符开头或结尾
    """
    if not username:
        return False, "用户名不能为空"

    if len(username) < 3 or len(username) > 32:
        return False, "用户名长度必须在 3-32 个字符之间"

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9_-]{1,30}[a-zA-Z0-9]$", username):
        return False, "用户名必须以字母开头和结尾，只能包含字母、数字、下划线和连字符"

    return True, ""


def validate_email(email: str) -> tuple[bool, str]:
    """验证邮箱格式"""
    if not email:
        return False, "邮箱不能为空"

    # 简单的邮箱格式检查
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, email):
        return False, "邮箱格式不正确"

    if len(email) > 254:
        return False, "邮箱地址过长"

    return True, ""


def validate_phone(phone: str) -> tuple[bool, str]:
    """验证手机号码（中国大陆）"""
    if not phone:
        return False, "手机号不能为空"

    if not re.match(r"^1[3-9]\d{9}$", phone):
        return False, "手机号格式不正确，请输入 11 位中国大陆手机号"

    return True, ""


def sanitize_input(value: str, max_length: int = 200) -> str:
    """
    清理用户输入：去除首尾空格、截断过长字符串、移除危险字符
    """
    if not value:
        return ""

    # 去除首尾空格
    value = value.strip()

    # 截断
    if len(value) > max_length:
        value = value[:max_length]

    # 移除不可见控制字符（除了换行和制表符）
    value = "".join(c for c in value if c.isprintable() or c in "\n\t\r")

    return value
