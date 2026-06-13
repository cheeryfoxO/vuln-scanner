# Vuln Scanner 🔍

[English](#english) | [中文](#中文)

---

## English

A modular CLI vulnerability reconnaissance tool written in Python. Plugin-based architecture — add new scan modules by creating a single file.

### Features

| Module | What it does |
|--------|-------------|
| **subdomain** | DNS resolution + HTTP liveness check (183 built-in prefixes) |
| **dirscan** | HEAD probe sensitive paths with 404 false-positive filtering (248 built-in paths) |
| **params** | Extract form inputs, JS API endpoints, URL query parameters |

### Installation

```bash
git clone https://github.com/cheeryfoxO/vuln-scanner.git
cd vuln-scanner
pip install -e .
```

### Quick Start

```bash
# List available modules
scanner list

# Enumerate subdomains
scanner scan example.com -m subdomain -v

# Scan sensitive directories
scanner scan https://example.com -m dirscan -v

# Extract input points
scanner scan https://example.com -m params -v

# Run all modules + save report
scanner scan https://example.com -m all -v -o report.json
```

### CLI Reference

```
scanner scan <target> [options]

  -m, --modules    Modules to run: subdomain,dirscan,params or all (default: all)
  -t, --threads    Concurrency threads (default: 10)
  -o, --output     Save JSON report to file
  -v, --verbose    Show progress output
  --timeout <n>    Request timeout in seconds (default: 10)
  --no-color       Disable colored output
```

### Example Output

```
[*] Starting scan against baidu.com
[*] Loaded 183 subdomain prefixes, resolving DNS...
[subdomain] www.baidu.com - 200 - 百度一下
[subdomain] api.baidu.com - 200
[subdomain] news.baidu.com - 200 - 百度新闻
...
Scan complete. 34 findings across 1 modules.
```

### Adding a New Module

1. Create a file in `scanner/modules/`:

```python
from scanner.modules.base import BaseModule

class MyModule(BaseModule):
    name = "mymodule"
    description = "My custom scanner"
    requires_url = True

    def run(self, target, request_handler, output):
        findings = []
        # ... your scan logic here ...
        return {"module": self.name, "findings": findings}
```

2. Register in `scanner/cli.py` by adding `MyModule` to `MODULE_CLASSES`.

### Tech Stack

Python 3.13, requests, colorama, concurrent.futures (stdlib)

---

## 中文

用 Python 写的模块化漏洞侦察 CLI 工具。插件式架构——新增扫描模块只需新建一个文件。

### 功能

| 模块 | 作用 |
|------|------|
| **subdomain** | DNS 解析 + HTTP 存活检测（内置 183 条子域名前缀） |
| **dirscan** | HEAD 请求探测敏感路径，404 误报过滤（内置 248 条路径） |
| **params** | 提取表单输入点、JS API 端点、URL 查询参数 |

### 安装

```bash
git clone https://github.com/cheeryfoxO/vuln-scanner.git
cd vuln-scanner
pip install -e .
```

### 快速开始

```bash
# 查看可用模块
scanner list

# 子域名枚举
scanner scan example.com -m subdomain -v

# 目录探测
scanner scan https://example.com -m dirscan -v

# 参数分析
scanner scan https://example.com -m params -v

# 全部模块 + 保存 JSON 报告
scanner scan https://example.com -m all -v -o report.json
```

### 命令行参数

```
scanner scan <目标> [选项]

  -m, --modules    选择模块 (subdomain,dirscan,params 或 all)
  -t, --threads    并发线程数 (默认: 10)
  -o, --output     保存 JSON 报告
  -v, --verbose    显示详细进度
  --timeout <n>    请求超时秒数 (默认: 10)
  --no-color       关闭彩色输出
```

### 添加新模块

1. 在 `scanner/modules/` 下新建文件，继承 `BaseModule`
2. 在 `scanner/cli.py` 的 `MODULE_CLASSES` 列表加一行注册

### 技术栈

Python 3.13 / requests / colorama / concurrent.futures（标准库）
