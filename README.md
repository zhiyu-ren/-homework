# 🏫 -homework

> 每天会更新作业内容

---

## 📋 作业导航

| 日期 | 目录 | 内容 | 技术栈 |
|:----:|:----:|:----|:------:|
| 🟢 **Day 01** | — | 环境搭建 & NPS 默认密码检测工具 | Python / FOFA |
| 🟢 **Day 02** | [`Class02/`](./Class02) | 用户信息管理系统（安全加固版） | Flask / SQLite / PBKDF2 |
| ⬜ Day 03 | `Class03/` | *待更新...* | — |
| ⬜ Day 04 | `Class04/` | *待更新...* | — |
| ⬜ Day 05 | `Class05/` | *待更新...* | — |

> 💡 **提示：** 以后每天新建 `ClassXX/` 目录放入当天作业，然后在本 README 的作业导航表中添加一行即可。

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
