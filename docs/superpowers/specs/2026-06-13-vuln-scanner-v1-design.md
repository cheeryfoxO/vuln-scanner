# Vulnerability Scanner v1 — Design Spec

**Date:** 2026-06-13
**Status:** Draft → Awaiting review
**Goal:** Python CLI 综合漏洞扫描工具，插件式架构，支持逐步扩展模块

## 1. Overview

一个模块化的命令行漏洞扫描工具，Phase 1 包含三个侦察模块：子域名枚举、目录/文件探测、参数分析。插件式架构设计，后续新增模块只需新建一个文件并注册，无需改动核心代码。

**用户画像：** 有 Web 安全基础、会 Python、想通过造轮子加深理解并用于授权测试。

## 2. CLI Interface

```
用法:
  scanner scan <target> [options]    对目标执行扫描
  scanner list                       列出可用模块

扫描选项:
  -m, --modules <name,...>   选择模块 (默认: all)
                             可用: subdomain, dirscan, params
  -t, --threads <n>          并发线程数 (默认: 10)
  -o, --output <path>        输出 JSON 报告到文件
  -v, --verbose              详细输出
  --timeout <n>              请求超时秒数 (默认: 10)
  --no-color                 关闭彩色输出

示例:
  scanner scan example.com -m subdomain,dirscan -t 20
  scanner scan https://target.com -m params -o report.json -v
  scanner list
```

- 子命令模式：`scan` 为主命令，日后可扩展 `scan --resume`、`config`
- 目标 URL 自动补全协议：不写 `https://` 默认 `http://`
- `-m all` 按合理顺序执行：子域名 → 目录探测 → 参数分析（后两者可并行）

## 3. Project Structure

```
scanner/
├── cli.py              # 入口，argparse 解析，调度
├── core/
│   ├── engine.py       # 扫描引擎（队列、并发控制、结果收集）
│   ├── request.py      # HTTP 请求封装（重试、UA 轮换、超时）
│   └── output.py       # 输出格式化（终端彩色 / JSON）
├── modules/
│   ├── base.py         # 模块基类，定义接口
│   ├── subdomain.py    # 子域名枚举 + 存活检测
│   ├── dirscan.py      # 目录/文件探测
│   └── params.py       # 参数分析
└── data/
    ├── subdomains.txt  # 子域名字典（~200 条）
    └── dirs.txt        # 路径字典（~300 条）
```

## 4. Engine Architecture

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│   cli.py     │────▶│    Engine       │────▶│  Output      │
│  (argparse)  │     │  ┌───────────┐  │     │  (terminal/  │
│              │     │  │ Scheduler  │  │     │   JSON)     │
└──────────────┘     │  ├───────────┤  │     └──────────────┘
                     │  │ ThreadPool │  │
┌──────────────┐     │  ├───────────┤  │
│  modules/    │────▶│  │ Collector  │  │
│  subdomain   │     │  └───────────┘  │
│  dirscan     │     └─────────────────┘
│  params      │
└──────────────┘
```

**职责：**
- 接收 target / modules / threads / timeout，装配执行计划
- `concurrent.futures.ThreadPoolExecutor` 统一管理全部并发任务
- 模块执行顺序：subdomain → dirscan（对发现的子域名）→ params 可与 dirscan 并行
- Collector 聚合统一格式的结果：`{"module": "subdomain", "findings": [...]}`

**并发策略：** 线程池（非异步），保证调用栈可读、调试友好。

## 5. Module Specifications

### 5.1 Base Module Interface

```python
class BaseModule:
    name: str              # "subdomain"
    description: str       # 模块描述
    requires_target: bool  # 是否需要 URL 前缀

    def run(self, target: str, engine: "Engine") -> dict:
        """返回 {"module": self.name, "findings": [...]}"""
        ...
```

### 5.2 Subdomain Enumeration

| 项目 | 详情 |
|------|------|
| 输入 | example.com（纯域名） |
| 字典 | 内置 ~200 条常见子域名前缀 |
| DNS 解析 | `socket.getaddrinfo()`，零依赖 |
| 存活检测 | HTTP GET 请求每个解析成功的子域名 |
| 输出 | 子域名、IP、HTTP 状态码、页面标题 |

### 5.3 Directory/File Scanning

| 项目 | 详情 |
|------|------|
| 输入 | http://example.com（完整 URL） |
| 字典 | 内置 ~300 条（敏感文件、备份、管理后台、常见路径） |
| 方法 | HTTP HEAD 请求，节省带宽 |
| 结果分类 | 200(绿)、301(黄)、401/403(红)、404(灰) |
| 404 误报处理 | 先请求随机路径做基线，过滤相同响应 |
| 输出 | 路径、状态码、Content-Type、Content-Length |

### 5.4 Parameter Analysis

| 项目 | 详情 |
|------|------|
| 输入 | http://example.com（完整 URL） |
| HTML 解析 | 标准库 `html.parser`，提取 `<form>`、`<a>`、`<script>`、`<link>` |
| JS 分析 | 正则匹配 `fetch()`, `axios()`, `$.ajax()` 等 API 调用模式 |
| URL 参数 | 提取当前页面 URL query string 参数 |
| 输出 | 分类：表单输入点、JS 端点、URL 参数 |

## 6. Output Format

### Terminal (default)
- 彩色输出：绿色=200, 黄色=301, 红色=403, 灰色=404
- Windows 兼容：`colorama`
- `-v` 模式打印实时进度（已完成 X/Y）
- 静默模式只输出发现的结果

### JSON Report (`-o report.json`)
```json
{
  "scan_time": "2026-06-13T14:30:00",
  "target": "example.com",
  "modules": ["subdomain", "dirscan"],
  "findings": {
    "subdomain": [
      {"host": "admin.example.com", "ip": "1.2.3.4", "status": 200, "title": "Admin Panel"}
    ],
    "dirscan": [
      {"url": "http://example.com/.git/HEAD", "status": 200, "size": 41, "content_type": "text/plain"}
    ]
  }
}
```

## 7. Dependencies

| 包 | 用途 | 备注 |
|----|------|------|
| `requests` | HTTP 请求 | 唯一核心外部依赖 |
| `colorama` | Windows 彩色终端 | 可选，缺失时降级为纯文本 |
| 其余全部 | Python 标准库 | `argparse`, `socket`, `html.parser`, `json`, `concurrent.futures`, `re`, `urllib.parse` |

## 8. Non-Goals (Phase 2+)

- SQL 注入 / XSS 检测模块 → Phase 2
- 断点续扫 (`--resume`) → Phase 2
- 自定义字典文件 → Phase 2
- tqdm 进度条 → Phase 2
- 插件热加载 → 不计划

## 9. Success Criteria

1. `scanner scan example.com` 跑完全部 3 个模块不崩溃
2. 对已知有子域名的测试目标能发现至少 1 个子域名
3. 对本地搭的测试站点能发现模拟的敏感路径
4. JSON 报告格式正确可解析
5. 每个模块可独立运行和组合运行
