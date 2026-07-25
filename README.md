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
| 🟢 **Day 05** | [`Class05/`](./Class05) | Class04基础上新增个人中心+充值，修复业务逻辑漏洞 | Flask / Session校验 / 金额校验 |
| 🟢 **Day 06** | [`Class06/`](./Class06) | Class05基础上新增动态页面加载，修复路径遍历漏洞 | Flask / 白名单 / 路径校验 |
| 🟢 **Day 07** | [`Class07/`](./Class07) | Class06基础上新增修改密码，修复CSRF/越权/无密码验证漏洞 | Flask / CSRF Token / 密码验证 |
| 🟢 **Day 08** | [`Class08/`](./Class08) | SSTI漏洞演示+修复 + SSTI扫描器 | Flask / render_template_string / Python |

> 💡 **提示：** 以后每天新建 `ClassXX/` 目录放入当天作业，然后在本 README 的作业导航表中添加一行即可。

---

## 🟢 Day 01 — 环境搭建 & NPS 默认密码检测

📂 根目录脚本

> NPS（内网穿透代理）默认密码 `admin/123` 批量检测工具。通过 FOFA 获取资产后进行登录验证。

### 技术栈

`Python` · `FOFA` · `urllib` · `SSL Bypass`

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

`Flask` · `PBKDF2-SHA256` · `SQLite` · `Flask-WTF` · `CSRF` · `Rate Limiting`

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

## 🟢 Day 05 — 新增个人中心+充值 & 业务逻辑漏洞修复

📂 目录：[`Class05/`](./Class05)

> 在 Class04 基础上新增个人中心和充值功能，并修复业务逻辑漏洞（水平越权、负值交易）。

### 新增功能

| 功能 | 路由 | 说明 |
|:----|:----:|:------|
| 👤 个人中心 | `/profile` | 查看个人资料（ID、用户名、邮箱、手机、余额） |
| 💰 充值 | `/recharge` | 余额充值 |

### 修复的漏洞

| 漏洞 | 风险等级 | 修复方式 |
|:-----|:--------:|:---------|
| 水平越权（可查看任意用户资料） | 🔴 **严重** | ✅ session获取用户身份 |
| 负值交易（可传入负数扣减余额） | 🟠 **高危** | ✅ 金额必须大于0 |
| 跨越充值（给其他用户充值） | 🟠 **高危** | ✅ session获取用户ID |

### 修复前后对比

| 维度 | 修复前（漏洞版） | 修复后（安全版） |
|:-----|:----------------|:----------------|
| `/profile` | `?user_id=X` 可查任意用户 | 只能查看自己的资料 |
| `/recharge` | 可给任意用户+任意金额 | 只能给自己充正数 |

[📄 完整漏洞修复报告 →](./Class05/业务逻辑漏洞与水平越权漏洞修复报告.md)

### 快速启动

```bash
cd Class05
pip install -r requirements.txt
python3 app.py
```

**测试账号：** `admin` / `Admin@2025Secure!`

---

## 🟢 Day 06 — 新增动态页面加载 & 路径遍历漏洞修复

📂 目录：[`Class06/`](./Class06)

> 在 Class05 基础上新增动态页面加载功能，并修复路径遍历漏洞。

### 新增功能

| 功能 | 路由 | 说明 |
|:----|:----:|:------|
| 📄 动态页面加载 | `/page?name=help` | 加载帮助中心页面 |

### 修复的漏洞

| 漏洞 | 风险等级 | 修复方式 |
|:-----|:--------:|:---------|
| 路径遍历（可读取任意文件） | 🔴 **严重** | ✅ 页面白名单 + 固定.html后缀 |

### 白名单机制

```python
ALLOWED_PAGES = {"help", "about", "contact"}
if name not in ALLOWED_PAGES:
    return "页面不存在"
```

[📄 完整漏洞修复报告 →](./Class06/新增功能与路径遍历漏洞修复报告.docx)

### 快速启动

```bash
cd Class06
pip install -r requirements.txt
python3 app.py
```

**测试账号：** `admin` / `Admin@2025Secure!`

---

## 🟢 Day 07 — 新增修改密码 & CSRF/越权漏洞修复

📂 目录：[`Class07/`](./Class07)

> 在 Class06 基础上新增修改密码功能，并修复CSRF、水平越权、无原密码验证漏洞。

### 新增功能

| 功能 | 路由 | 说明 |
|:----|:----:|:------|
| 🔑 修改密码 | `/change-password` (POST) | 验证原密码后修改密码 |

### 修复的漏洞

| 漏洞 | 风险等级 | 修复方式 |
|:-----|:--------:|:---------|
| CSRF跨站请求伪造 | 🟡 **中危** | ✅ HMAC CSRF Token验证 |
| 水平越权（可修改他人密码） | 🔴 **严重** | ✅ session获取当前用户 |
| 无原密码验证 | 🟠 **高危** | ✅ 必须验证原密码 |

### 修复前后对比

| 维度 | 修复前 | 修复后 |
|:-----|:-------|:-------|
| CSRF Token | ❌ 无 | ✅ HMAC验证 |
| 目标用户来源 | 表单隐藏字段 | ✅ session当前用户 |
| 原密码验证 | ❌ 无 | ✅ 必须验证 |

[📄 完整漏洞修复报告 →](./Class07/CSRF漏洞修复报告.docx)

### 快速启动

```bash
cd Class07
pip install -r requirements.txt
python3 app.py
```

**测试账号：** `admin` / `Admin@2025Secure!`

---

## 🟢 Day 08 — SSTI漏洞演示+修复 & SSTI扫描器

📂 目录：[`Class08/`](./Class08)

> 在 Class07 基础上新增欢迎页和反馈功能（含SSTI漏洞并修复），并附带SSTI扫描器脚本。

### 新增功能

| 功能 | 路由 | 说明 |
|:----|:----:|:------|
| 👋 欢迎页 | `/welcome?name=X` | 个性化欢迎页面 |
| 💬 反馈 | `/feedback` | 用户反馈表单 |

### 修复的SSTI漏洞

| 漏洞 | 风险等级 | 修复方式 |
|:-----|:--------:|:---------|
| welcome页SSTI（f-string拼接name） | 🔴 **严重** | ✅ Jinja2变量 {{ name }} 传递 |
| feedback页SSTI（f-string拼接name/message） | 🔴 **严重** | ✅ Jinja2变量 {{ name }} {{ message }} 传递 |

### 修复前后对比

| 维度 | 修复前（漏洞版） | 修复后（安全版） |
|:-----|:----------------|:----------------|
| 模板渲染方式 | `f"...{name}..."` 先拼接后渲染 | `{{ name }}` Jinja2变量传递 |
| {{7*7}} 注入测试 | 计算为49 ✅注入成功 | 显示字符串"{{7*7}}" ❌注入失败 |
| HTML转义 | ❌ 无转义 | ✅ Jinja2自动转义 |

### SSTI扫描器

配套扫描脚本 `ssti_scanner.py`，可检测SSTI漏洞。

```bash
python3 ssti_scanner.py -u "http://target.com/" -p name
```

[📄 完整漏洞修复报告 →](./Class08/SSTI漏洞修复报告.docx)

### 快速启动

```bash
cd Class08
pip install -r requirements.txt
python3 app.py
```

**测试账号：** `admin` / `Admin@2025Secure!`

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
