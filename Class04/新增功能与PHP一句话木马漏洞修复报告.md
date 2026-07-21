# Day 04 — 新增头像上传功能 & PHP一句话木马漏洞修复报告

> **项目目录**: [`Class04/`](./Class04)
> **日期**: 2026-07-21
> **技术栈**: Flask / SQLite / Werkzeug

---

## 一、新增功能：头像上传

在原有登录、注册、搜索功能基础上，新增**用户头像上传**功能。

### 1.1 功能说明

| 项目 | 内容 |
|:-----|:------|
| 路由 | `/upload` (GET/POST) |
| 上传目录 | `static/uploads/` |
| 存储方式 | UUID 重命名 + 白名单扩展名 |
| 数据库字段 | `users.avatar` 存储文件名 |
| 头像展示 | 首页个人信息区域显示圆形头像 |

### 1.2 功能流程

```
用户登录 → 点击"上传头像" → 选择图片文件
    ↓
服务端安全校验（扩展名 + MIME + 幻数）
    ↓
UUID重命名保存到 static/uploads/
    ↓
更新数据库 users.avatar 字段
    ↓
首页显示用户头像
```

### 1.3 头像显示效果

- **有头像**: 显示圆形裁剪的头像图片（100px × 100px，蓝色边框）
- **无头像**: 显示用户名首字母的彩色圆形占位（如 admin → `A`）

---

## 二、PHP一句话木马上传漏洞分析

### 2.1 漏洞概述

头像上传功能如果不对上传文件做任何检查，攻击者可上传包含 PHP 代码的恶意文件（一句话木马），从而获取服务器控制权。

### 2.2 一句话木马示例

```php
<?php @eval($_POST['ant']); ?>
```

如果该文件被上传到 `static/uploads/` 目录并以 `.php` 结尾，攻击者访问该文件并 POST 参数 `ant=system('id');` 即可执行任意命令。

### 2.3 常见上传绕过方式

| 绕过方式 | 原理 |
|:---------|:------|
| 修改扩展名 | `.php` → `.php5` / `.phtml` / `.PhP` |
| 修改 MIME | 抓包将 `Content-Type` 改为 `image/jpeg` |
| 图片马 | `GIF89a<?php @eval($_POST['ant']);?>` |
| 双重扩展 | `shell.php.jpg`（Apache从右解析） |
| `.htaccess` | 上传配置文件让 Apache 把图片当PHP解析 |
| `%00`截断 | `shell.php%00.jpg` |
| 文件头伪造 | 在PHP代码前加GIF89a头欺骗幻数检查 |

---

## 三、安全修复方案

### 3.1 修复策略 — 五层白名单校验

```
用户上传文件
    ↓
① 扩展名白名单 → 仅允许 .jpg .jpeg .png .gif
    ↓
② MIME类型校验 → 仅允许 image/jpeg image/png image/gif
    ↓
③ 文件幻数校验 → 检查文件头部标识字节
    ↓
④ UUID重命名 → 防止路径穿越 / 覆盖关键文件
    ↓
⑤ 非PHP目录 → 上传目录不解析PHP（.htaccess配置）
```

### 3.2 关键代码实现

#### ① 扩展名白名单

```python
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif'}

_, ext = os.path.splitext(filename)
ext = ext.lower()
if ext not in ALLOWED_EXTENSIONS:
    return render_template("upload.html", error="不允许上传该类型文件")
```

#### ② MIME类型校验

```python
ALLOWED_MIMES = {'image/jpeg', 'image/png', 'image/gif'}

if file.content_type not in ALLOWED_MIMES:
    return render_template("upload.html", error="文件类型不正确")
```

#### ③ 文件幻数校验

```python
def check_magic(filepath):
    with open(filepath, 'rb') as f:
        h = f.read(12)
    if h[:3] == b'\xff\xd8\xff':   # JPEG
        return '.jpeg'
    if h[:4] == b'\x89PNG':         # PNG
        return '.png'
    if h[:6] in (b'GIF89a', b'GIF87a'):  # GIF
        return '.gif'
    return None  # 非法文件
```

#### ④ UUID重命名

```python
import uuid
final_name = f"{uuid.uuid4().hex}{real_ext}"
```

使用 UUID 替代用户上传的原始文件名，可彻底防御：
- 路径穿越攻击 `../../etc/passwd`
- 覆盖系统关键文件
- 文件名包含恶意字符串

---

## 四、修复前后对比

| 安全维度 | 修复前 (Class03) | 修复后 (Class04) |
|:---------|:-----------------|:-----------------|
| 扩展名检查 | ❌ 无 | ✅ 白名单 `.jpg/.jpeg/.png/.gif` |
| MIME校验 | ❌ 无 | ✅ `image/jpeg` `image/png` `image/gif` |
| 文件幻数检查 | ❌ 无 | ✅ JPEG/PNG/GIF 头部标识 |
| 文件名处理 | 原始文件名 | ✅ UUID 重命名 + `secure_filename` |
| 路径穿越防护 | ❌ 无 | ✅ UUID 重命名 + Werkzeug 安全函数 |
| 文件大小限制 | 无 | ✅ 16MB |
| PHP代码上传 | ✅ 可上传 | ❌ 被拦截 |
| .htaccess上传 | ✅ 可上传 | ❌ 被拦截（扩展名不在白名单） |

---

## 五、PHP一句话木马免杀与防御对照

| 攻击手法 | 绕过方式 | 防御措施 |
|:---------|:---------|:---------|
| 直接上传 `.php` | 修改扩展名 | 扩展名白名单 ❌ |
| 修改 `Content-Type` | Burp抓包改MIME | 服务端MIME校验 ✅ |
| 图片马 GIF89a + PHP代码 | 文件头+代码混合 | 幻数校验 + 扩展名匹配 ✅ |
| 双重扩展 `.php.jpg` | Apache解析漏洞 | UUID重命名 ✅ |
| `.htaccess` 上传 | 配置Apache解析 | 扩展名白名单 ❌ |
| 变量函数 `$a=eval;$a()` | 绕过关键字检测 | 文件扩展名白名单 ✅ |
| base64编码 `base64_decode` | 编码隐藏代码 | 文件扩展名白名单 ✅ |
| 图片EXIF藏代码 | 元数据中隐藏 | 需结合WAF检测 |

---

## 六、参考代码：upload-labs 防御示例

你提供的参考代码使用了**黑名单机制**：

```php
$deny_ext = array(".php",".php5",".phtml",".asp",".aspx",".htaccess",".ini",...);
$file_ext = strtolower($file_ext);
$file_ext = str_ireplace('::$DATA', '', $file_ext);

if (!in_array($file_ext, $deny_ext)) {
    move_uploaded_file($temp_file, $img_path);
}
```

### 黑名单 vs 白名单

| 对比项 | 黑名单 | 白名单（本方案） |
|:-------|:-------|:----------------|
| 维护成本 | ❌ 需要不断更新 | ✅ 只需列出允许类型 |
| 安全性 | ❌ 总有遗漏（如 `.php5` `.pht`） | ✅ 不在列表即拒绝 |
| 绕过难度 | ⭐ 低（易找到未封的扩展名） | ⭐⭐⭐ 高 |
| 推荐度 | ❌ 不推荐 | ✅ 推荐 |

---

## 七、防御建议清单

| 优先级 | 措施 | 说明 |
|:------:|:-----|:------|
| 🔴 必做 | **扩展名白名单** | 只允许图片类型，拒绝所有可执行扩展名 |
| 🔴 必做 | **UUID重命名** | 防止路径穿越和文件名攻击 |
| 🔴 必做 | **文件幻数校验** | 防止图片马和伪造文件头 |
| 🟠 建议 | **上传目录禁止执行PHP** | 通过 `.htaccess` 或 Nginx 配置关闭PHP解析 |
| 🟠 建议 | **文件大小限制** | 防止DOS攻击填满磁盘 |
| 🟡 可选 | **图片二次渲染** | 使用 GD/Imagick 重新生成图片，彻底清除木马代码 |
| 🟡 可选 | **WAF检测** | 长亭雷池等WAF检测请求内容中的恶意代码 |
| 🟡 可选 | **日志审计** | 记录所有上传行为，便于事后追溯 |

---

## 八、启动方式

```bash
cd /opt/Class04
pip install -r requirements.txt
python3 app.py
```

访问 http://localhost:5000

**测试账号**: `admin` / `Admin@2025Secure!`
