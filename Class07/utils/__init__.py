"""
用户信息管理系统
=================
基于 Flask 的安全用户管理平台

功能：
  - 用户注册与登录
  - 个人信息查看与管理
  - 安全的密码哈希存储
  - 全链路加密与 CSRF 防护

安全特性：
  - 密码 PBKDF2-SHA256 哈希存储
  - Flask-Limiter 登录限流
  - CSRF 令牌保护
  - Session 安全配置
  - 强制密码策略
  - 账户锁定机制
  - 安全日志审计
  - 安全响应头

技术栈：Flask + Werkzeug + WTForms + SQLite3
"""
