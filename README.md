# 🏫 -homework

> 每天会更新作业内容

---

## 📋 作业导航

| 日期 | 目录 | 内容 | 技术栈 |
|:----:|:----:|:----|:------:|
| 🟢 **Day 01** | — | 环境搭建 & NPS 默认密码检测工具 | Python / FOFA |
| 🟢 **Day 02** | [`Class02/`](./Class02) | 用户信息管理系统（安全加固版） | Flask / SQLite / PBKDF2 |
| 🟢 **Day 03** | [`Class03/`](./Class03) | Class02基础上新增注册+搜索，修复SQL注入 | Flask / SQLite / 参数化查询 |
| 🟢 **Day 04** | [`Class04/`](./Class04) | Class03基础上新增头像上传，修复一句话木马漏洞 | Flask / 白名单 / 幻数校验 |
| ⬜ Day 05 | `Class05/` | *待更新...* | — |

> 💡 **提示：** 以后每天新建 `ClassXX/` 目录放入当天作业，然后在本 README 的作业导航表中添加一行即可。

---

## 🟢 Day 04 — 新增头像上传 & 一句话木马漏洞修复

📂 目录：[`Class04/`](./Class04)

> 在 Class03 基础上新增用户头像上传功能，并通过五层白名单校验修复 PHP 一句话木马上传漏洞。

### 新增功能

| 功能 | 路由 | 说明 |
|:----|:----:|:------|
| 📸 头像上传 | `/upload` | 支持 JPG/PNG/GIF 格式上传，首页显示 |

### 修复的漏洞

| 漏洞 | 风险等级 | 修复方式 |
|:-----|:--------:|:---------|
| 任意文件上传（可传PHP木马） | 🔴 严重 | ✅ 扩展名白名单 |
| MIME类型伪造 | 🟠 高危 | ✅ 服务端MIME校验 |
| 图片马（GIF89a+PHP代码） | 🟠 高危 | ✅ 文件幻数校验 |
| 路径穿越 `../../` | 🟠 高危 | ✅ UUID重命名 + Werkzeug安全函数 |
| 文件名注入攻击 | 🟡 中危 | ✅ UUID重命名 |

### 五层安全校验

```
上传文件 → 扩展名白名单 → MIME校验 → 幻数校验 → UUID重命名 → 保存
```

[📄 完整漏洞修复报告 →](./Class04/新增功能与PHP一句话木马漏洞修复报告.md)

### 快速启动

```bash
cd Class04
pip install -r requirements.txt
python3 app.py
```

**测试账号：** `admin` / `Admin@2025Secure!`

---

## 🟢 Day 03 — 新增注册+搜索功能 & SQL注入修复

📂 目录：[`Class03/`](./Class03)

> 在 Class02 安全加固版基础上新增用户注册和用户搜索功能，并对新功能中的 SQL 注入漏洞进行完整修复。

### 新增功能

| 功能 | 路由 | 说明 |
|:----|:----:|:------|
| 📝 用户注册 | `/register` | 支持用户名、密码、邮箱、手机号注册 |
| 🔍 用户搜索 | `/search` | 模糊搜索用户名/邮箱，表格展示结果 |

### 修复的SQL注入漏洞

| 漏洞位置 | 风险等级 | 修复方式 |
|:---------|:--------:|:---------|
| 注册功能 f-string 拼接 INSERT | 🔴 严重 | ✅ 参数化查询（`?`占位符） |
| 搜索功能 f-string 拼接 LIKE | 🔴 严重 | ✅ 参数化查询（`?`占位符） |

### 附加强安全措施

- ✅ CSRF令牌保护
- ✅ 强密码策略（12位+复杂度+黑名单）
- ✅ 输入验证（用户名/邮箱/手机号格式校验）
- ✅ 速率限制（每IP每小时3次注册）
- ✅ 安全审计日志

[📄 完整报告 →](./Class03/新增功能与SQL漏洞修复报告.docx)

### 快速启动

```bash
cd Class03
pip install -r requirements.txt
cp .env.example .env
python3 app.py
```

**测试账号：** `admin` / `Admin@2025Secure!`

---

## 🟢 Day 02 — 用户信息管理系统（安全加固版）

📂 目录：[`Class02/`](./Class02)

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1.3-green)](https://flask.palletsprojects.com)
[![Security](https://img.shields.io/badge/Security-Enhanced-red)]()

> 一个基于 Flask 的用户信息管理平台，从零开始构建并进行了全面的安全加固。
> 同时包含**原始漏洞版本**与**安全加固版本**的对比，可作为安全培训的实践案例。

### 漏洞修复清单（15 项）

| 漏洞 | 等级 | 修复方式 |
|:----|:----:|:---------|
| 密码明文存储 | 🔴 **严重** | PBKDF2-SHA256 哈希 |
| HTML 注释泄露密码 | 🔴 **严重** | 已删除 |
| 模板显示密码 | 🟠 **高危** | 移除密码字段 |
| Secret Key 硬编码 | 🟠 **高危** | 环境变量读取 |
| Debug 模式开启 | 🟠 **高危** | 环境变量控制 |
| 无登录限流 | 🟠 **高危** | 每分钟 10 次 |
| 错误信息枚举用户 | 🟠 **高危** | 统一提示 |
| 无 CSRF 保护 | 🟡 **中危** | HMAC 令牌 |
| Session 安全缺失 | 🟡 **中危** | HttpOnly+SameSite+30min |
| 输入验证缺失 | 🟡 **中危** | 格式校验+清理 |
| 密码策略缺失 | 🟡 **中危** | 12位+复杂度+黑名单 |
| 无账户锁定 | 🟡 **中危** | 5次失败锁定15分钟 |
| 安全日志缺失 | 🔵 **低危** | 文件+控制台 |
| 安全响应头缺失 | 🔵 **低危** | 7 项安全头 |
| 内存字典存储 | 🔵 **低危** | SQLite 持久化 |

### 快速启动

```bash
cd Class02
pip install -r requirements.txt
cp .env.example .env
python3 app.py
```

访问 http://localhost:5000

**测试账号：** `admin` / `Admin@2025Secure!`

### 技术栈

`Flask` · `PBKDF2-SHA256` · `SQLite` · `Flask-WTF` · `CSRF` · `Rate Limiting`

---

## 🟢 Day 01 — 环境搭建 & NPS 默认密码检测

📂 根目录脚本

> NPS（内网穿透代理）默认密码 admin/123 批量检测工具。通过 FOFA 获取资产后进行登录验证。

### 技术栈

`Python` · `FOFA` · `urllib` · `SSL Bypass`

---

## 📝 模板：新增每日作业

以后每天添加新作业时，请按以下步骤操作：

```bash
# 1. 创建当天目录
mkdir ClassXX

# 2. 放入作业文件
# ...

# 3. 更新 README：在"作业导航"表中新增一行
#    并在下方添加 "Day XX — xxx" 章节

# 4. 提交推送
git add ClassXX/ README.md
git commit -m "Day XX: xxx"
git push
```

---
