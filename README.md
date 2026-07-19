# -homework
每天会更新作业内容

---

# 用户信息管理系统（安全加固版）

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1.3-green)](https://flask.palletsprojects.com)
[![Security](https://img.shields.io/badge/Security-Enhanced-red)]()

> 一个基于 Flask 的用户信息管理平台，从零开始构建并进行了全面的安全加固。
> 本项目同时包含**原始漏洞版本**与**安全加固版本**的对比，可作为安全培训的实践案例。

---

## 📋 目录

- [项目概述](#项目概述)
- [漏洞修复清单](#漏洞修复清单)
- [快速开始](#快速开始)
- [项目结构](#项目结构)
- [安全架构](#安全架构)
- [API 端点](#api-端点)
- [部署指南](#部署指南)

---

## 项目概述

本项目演示了一个简单的用户信息管理平台，并经历了从**存在严重安全漏洞**到**全面安全加固**的完整过程。

### 原始版本的漏洞

原始版本存在以下严重安全问题：

| 漏洞分类 | 具体问题 | 风险等级 |
|:---------|:---------|:--------:|
| 密码存储 | 明文存储密码 | 🔴 **严重** |
| 信息泄露 | HTML 注释暴露默认账号密码 | 🔴 **严重** |
| 信息泄露 | 模板显示用户密码明文 | 🟠 **高危** |
| 配置安全 | Secret Key 硬编码 | 🟠 **高危** |
| 配置安全 | Debug 模式开启 | 🟠 **高危** |
| 暴力破解 | 无登录限流 | 🟠 **高危** |
| 暴力破解 | 无账户锁定机制 | 🟡 **中危** |
| CSRF | 无跨站请求伪造防护 | 🟡 **中危** |
| Session | 无安全属性配置 | 🟡 **中危** |
| 输入验证 | 无输入校验和清理 | 🟡 **中危** |
| 密码策略 | 无密码强度要求 | 🟡 **中危** |
| 审计日志 | 无安全日志记录 | 🔵 **低危** |
| 响应头 | 无安全响应头 | 🔵 **低危** |
| 错误处理 | 错误信息区分用户是否存在 | 🟠 **高危** |

---

## 漏洞修复清单

所有漏洞已通过以下方式修复：

- [x] **密码 PBKDF2-SHA256 哈希存储** — 使用 Werkzeug 的 `generate_password_hash`
- [x] **配置文件隔离** — Secret Key 从环境变量读取，不留默认值
- [x] **模板不显示密码** — 用户信息页面不包含密码字段
- [x] **删除调试注释** — 所有 HTML 注释中的敏感信息已移除
- [x] **调试模式环境变量控制** — 仅 `FLASK_ENV=development` 时开启
- [x] **登录限流** — 每分钟最多 10 次登录尝试
- [x] **账户锁定** — 5 次失败锁定 15 分钟
- [x] **CSRF 令牌保护** — 所有 POST 表单携带 CSRF 令牌
- [x] **Session 安全配置** — HttpOnly + SameSite=Lax + 30 分钟过期
- [x] **输入验证与清理** — 用户名、邮箱、手机号格式校验 + 注入清理
- [x] **强密码策略** — 12 位 + 大小写 + 数字 + 特殊字符 + 黑名单
- [x] **通用错误提示** — 不区分"用户不存在"和"密码错误"
- [x] **安全审计日志** — 记录所有登录/注册/登出行为
- [x] **安全响应头** — HSTS、X-Frame-Options、XSS 保护等
- [x] **SQLite 持久化** — 从内存字典升级为文件数据库

---

## 快速开始

### 前置条件

- Python 3.9+
- pip

### 安装与运行

```bash
# 1. 克隆仓库
git clone <your-repo-url>
cd Class02

# 2. （可选）创建虚拟环境
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. 安装依赖
pip install -r requirements.txt

# 4. 配置环境变量
cp .env.example .env
# 编辑 .env 文件，务必修改 SECRET_KEY

# 5. 初始化并启动
python3 app.py
```

访问 [http://localhost:5000](http://localhost:5000)

### 默认测试账号

| 用户名 | 密码 | 角色 |
|:------|:-----|:----:|
| admin | `Admin@2025Secure!` | admin |
| alice | `Alice@2025Secure!` | user |

> ⚠️ **生产环境务必删除或修改默认账号！**

---

## 项目结构

```
Class02/
├── app.py                    # 主应用入口
├── config.py                 # 配置管理（环境变量）
├── requirements.txt          # 依赖清单
├── .env.example              # 环境变量模板
├── .gitignore                # Git 忽略规则
├── README.md                 # 本文件
├── utils/
│   ├── __init__.py           # 模块初始化
│   ├── auth.py               # 认证工具（哈希、账户锁定）
│   ├── password_policy.py    # 密码策略验证
│   └── validators.py         # 输入验证与清理
├── templates/
│   ├── base.html             # 基础模板
│   ├── index.html            # 首页
│   ├── login.html            # 登录页
│   └── register.html         # 注册页
├── static/
│   └── css/
│       └── style.css         # 样式表
├── data/                     # 数据库文件（自动创建）
└── logs/                     # 日志文件（自动创建）
```

---

## 安全架构

### 认证流程

```
用户输入 → 输入验证 → CSRF 校验 → 限流检查 → 账户锁定检查
                                                    ↓
                                           密码哈希比对 (PBKDF2-SHA256)
                                                    ↓
                                   成功：生成 Session → 重置失败计数 → 跳转首页
                                   失败：记录失败 → 通用错误提示
```

### 密码存储

使用 Werkzeug 的 `generate_password_hash`（基于 PBKDF2-HMAC-SHA256）：

```
原始: Admin@2025Secure!
哈希: pbkdf2:sha256:600000$salt$hash
       ├── 算法 ──┴── 迭代 ──┴── 随机盐 ──┴── 哈希值
```

### 分层防御

```
┌─────────────────────────────────────────┐
│           安全响应头 (7 项)               │
├─────────────────────────────────────────┤
│           Session 安全配置                │
├─────────────────────────────────────────┤
│    CSRF 令牌    │    速率限制             │
├─────────────────────────────────────────┤
│    输入验证     │    密码策略             │
├─────────────────────────────────────────┤
│     账户锁定    │    安全日志             │
├─────────────────────────────────────────┤
│    PBKDF2-SHA256 密码哈希                │
└─────────────────────────────────────────┘
```

---

## API 端点

| 方法 | 路径 | 说明 | 认证 |
|:----|:-----|:----|:----:|
| GET | `/` | 首页 | 可选 |
| GET/POST | `/login` | 登录 | 否 |
| GET | `/logout` | 登出 | 否 |
| GET/POST | `/register` | 注册 | 否 |
| GET | `/health` | 健康检查 | 否 |

---

## 部署指南

### 生产环境部署

```bash
# 设置生产环境变量
export FLASK_ENV=production
export SESSION_COOKIE_SECURE=True
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

# 使用 Gunicorn 部署
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### HTTPS 配置（Nginx 反向代理）

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
    }
}
```

---

## 许可证

本项目仅用于教育和安全培训目的。
