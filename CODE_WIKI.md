# Code Wiki — 机场自动签到（SSPanel + GeeTest V4）

> 本文档是对 `jichang_checkin-main` 仓库的系统性代码说明，覆盖项目整体架构、模块职责、关键类与函数、依赖关系与运行方式。

---

## 1. 项目概览

### 1.1 项目定位

本项目是一个面向 **SSPanel** 机场的自动签到脚本，已针对 `https://ikuuu.win` 验证。核心解决了旧版签到脚本的以下痛点：

1. ikuuu 登录强制 **GeeTest V4 验证码**，旧脚本仅提交邮箱密码会被服务端拒绝（`phase=reset_login`）。
2. 旧脚本在登录失败时仍会“假装”执行签到，导致推送结果不可信。
3. 通知渠道单一且在 GitHub Actions 环境下 SMTP 端口常被封锁。

### 1.2 核心特性

| 特性 | 说明 |
| --- | --- |
| GeeTest V4 自动求解 | 接入社区项目 [GeekedTest](https://github.com/xKiian/GeekedTest)，登录时补齐 `host` / `pageLoadedAt` / `captcha_result` 浏览器字段 |
| 阶段化结果报告 | 登录、签到接口、主页验证三阶段独立判定 |
| 双重交叉验证 | 签到后重新读取账户主页，综合接口 `ret` 与页面状态判定，避免误报 |
| 多渠道通知 | Server酱 + SMTP / Resend 邮件，且检查实际投递结果 |
| 多种 SMTP 配置兼容 | 同时支持分组式（`SMTP_SERVER`/`SMTP_ACCOUNT`）与 Newapi-checkin 兼容的独立变量 |
| 多格式推送内容 | 纯文本 + Markdown + 响应式 HTML，适配不同渠道 |
| 流量奖励提取 | 从接口返回中正则提取流量奖励并单独展示 |
| URL 自动探测 | 配置为公告页（如 `ikuuu.co`）或返回 405 时自动回退到可用面板域名 |
| GitHub Actions 友好 | 自动检测 GHA 环境，优先使用 HTTPS 发信（Resend）绕过 SMTP 端口封锁 |

### 1.3 技术栈

- **语言**：Python 3.10+（使用 `from __future__ import annotations` 以兼容类型注解）
- **HTTP 客户端**：`requests`（主用），`curl_cffi`（GeekedTest 依赖）
- **验证码求解**：`GeekedTest`（运行时 vendoring，非 pip 依赖）
- **加密**：`pycryptodome`（GeekedTest 依赖）
- **CI/CD**：GitHub Actions（定时 cron + 手动触发）
- **测试**：Python 标准库 `unittest`

---

## 2. 项目结构

```text
jichang_checkin-main/
├── .github/
│   └── workflows/
│       └── main.yml              # GitHub Actions 工作流定义
├── tests/
│   └── test_main.py              # 离线单元测试（主页状态、SMTP 配置、通知、域名发现）
├── .gitignore
├── README.md                     # 面向用户的使用与部署文档
├── index.html                    # 落地页（即时跳转到 config_generator.html）
├── config_generator.html         # 网页配置生成器（表单→Secrets→一键跳转）
├── main.py                       # 核心脚本（唯一业务源文件）
└── requirements.txt              # Python 依赖清单
```

> 项目核心业务逻辑集中在 [main.py](file:///e:/Other/Github/jichang_checkin-main/main.py)。`geeked/` 目录在 CI 中按需 vendoring，不纳入版本库（见 `.gitignore`）。两个 HTML 文件为纯前端配置工具，无后端依赖，双击即可在浏览器运行或通过 GitHub Pages 托管。

---

## 3. 整体架构

### 3.1 架构分层

项目虽为单文件，但逻辑上可划分为五个清晰层次：

```text
┌──────────────────────────────────────────────────────────────┐
│  入口层 (main / CLI)                                          │
│  - main() / parse_accounts()                                 │
└───────────────────────────────┬──────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────┐
│  签到编排层 (Orchestration)                                    │
│  - sign_one() : 登录 → 主页验证 → 签到 → 主页再验证            │
└───────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐
│  登录/签到层     │  │  主页验证层       │  │  验证码层            │
│  login()        │  │  inspect_        │  │  solve_captcha()    │
│  checkin()      │  │  dashboard()     │  │  (依赖 geeked)       │
│  build_session()│  │  parse_dashboard_│  └─────────────────────┘
│  ajax_headers() │  │  state()         │
│                 │  │  _DashboardParser│
│  resolve_base_  │  │  unwrap_origin_  │
│  url() / probe  │  │  body()          │
└─────────────────┘  └─────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────┐
│  通知层 (Notification)                                        │
│  - notify() → send_serverchan() / send_email()               │
│  - send_email() → send_email_resend() / send_email_smtp()    │
│  - build_notification() : 生成纯文本/Markdown/HTML            │
└───────────────────────────────┬──────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────┐
│  配置与工具层 (Config & Utils)                                │
│  - env() / SMTP 解析三件套 / 数据类 / parse_json_loose()      │
└──────────────────────────────────────────────────────────────┘
```

### 3.2 签到核心流程（时序）

```text
main()
  │
  ├─ resolve_base_url(URL_RAW)        # 探测可用面板域名
  │     └─ probe_panel_api()          # POST /auth/login 探活
  │
  ├─ parse_accounts(CONFIG)           # 解析多账号
  │
  └─ for each account:
        └─ sign_one(index, email, pwd)
              │
              ├─ build_session()
              ├─ login()                # 含 solve_captcha() 求解 GeeTest V4
              ├─ inspect_dashboard()    # 签到前主页状态
              │     └─ 若已签到 → 直接返回成功
              ├─ checkin()              # POST /user/checkin
              ├─ extract_traffic_reward()
              ├─ inspect_dashboard()    # 签到后主页状态（双重验证）
              └─ 综合判定 → AccountResult

  build_notification(results)          # 汇总为 纯文本/MD/HTML
  notify(title, plain, md, html)       # Server酱 + 邮件(Resend/SMTP)
  依据 exit code 返回
```

---

## 4. 模块职责详解

### 4.1 配置与工具层

负责从环境变量读取配置，并解析结构化参数。

| 函数 | 位置 | 职责 |
| --- | --- | --- |
| `env(name, default)` | [main.py:48](file:///e:/Other/Github/jichang_checkin-main/main.py#L48) | 安全读取环境变量并 strip |
| `parse_smtp_server(raw)` | [main.py:85](file:///e:/Other/Github/jichang_checkin-main/main.py#L85) | 从单个 Secret 解析 `host/port[/mode]`，支持单行或多行格式 |
| `parse_smtp_account(raw)` | [main.py:120](file:///e:/Other/Github/jichang_checkin-main/main.py#L120) | 解析 `user/pass/mail_to`，支持行分隔或 `;,|` 分隔 |
| `resolve_smtp_config()` | [main.py:138](file:///e:/Other/Github/jichang_checkin-main/main.py#L138) | 合并分组式与独立式 SMTP 变量，**独立变量优先**；返回 7 元组 |
| `parse_json_loose(text)` | [main.py:162](file:///e:/Other/Github/jichang_checkin-main/main.py#L162) | 宽松 JSON 解析：先 `json.loads`，失败则正则提取嵌入的 JSON 对象 |
| `mask_account(account)` | [main.py:203](file:///e:/Other/Github/jichang_checkin-main/main.py#L203) | 脱敏邮箱账号，仅保留首尾字符 |
| `checkin_timezone()` / `local_today()` | [main.py:378](file:///e:/Other/Github/jichang_checkin-main/main.py#L378) | 基于 IANA 时区判断“今天”，用于主页签到时间校验 |

### 4.2 URL 解析与面板探测层

处理 ikuuu 公告页与面板页的混淆问题。

| 函数 | 职责 |
| --- | --- |
| `host_from_url(url)` | 从 URL 提取小写 host |
| `normalize_base_url(url)` | 规范化为 `scheme://host`，丢弃路径 |
| `probe_panel_api(base)` | 向 `/auth/login` 发探测请求，依据 `405` / JSON 结构判定是否为真实 SSPanel API |
| `resolve_base_url(configured)` | 探测候选域名列表，自动切换到可用面板；命中 `ikuuu.co` 等公告页时自动回退 |

### 4.3 数据类（结果模型）

```python
@dataclass
class AccountResult:     # 单账号签到结果
    index: int
    account: str
    ok: bool
    stage: str           # 阶段：登录 / 已签到 / 签到并验证 / 签到验证失败 / ...
    message: str
    verification: str    # 主页验证说明
    reward: str          # 流量奖励，如 "1.25 GB"

@dataclass
class DashboardState:    # 主页状态
    status: str          # signed / unsigned / unknown
    authenticated: bool
    message: str

@dataclass
class DeliveryResult:    # 单次通知投递结果
    channel: str
    configured: bool     # 是否配置了该渠道
    ok: bool
    message: str
```

### 4.4 主页验证层

这是本项目最核心的“可信判定”机制，避免仅凭接口 `ret=1` 就误报成功。

| 函数 / 类 | 职责 |
| --- | --- |
| `_DashboardParser(HTMLParser)` | 解析 `/user` 主页 HTML，收集签到控件与 `last-checkin-time` 时间戳 |
| `parse_dashboard_state(html)` | 综合控件 disabled 状态、签到文案、上次签到时间，判定 `signed`/`unsigned`/`unknown` |
| `unwrap_origin_body(html)` | 解码 ikuuu 页面使用的 Base64 `originBody` 包裹层（含 8MB 防爆限制） |
| `inspect_dashboard(session)` | 拉取 `/user`，处理重定向/登录跳回，返回 `DashboardState` |

**主页判定逻辑（`parse_dashboard_state`）：**

1. 遍历控件，若控件 disabled 且文案含“已签到/今日已领取/明日再来”等标记 → `signed`
2. `last-checkin-time` 含今天日期 → `signed`
3. 控件文案为“签到/每日签到/立即签到”且未 disabled、含 checkin 动作 → `unsigned`
4. 其余 → `unknown`

### 4.5 登录与签到层

| 函数 | 职责 |
| --- | --- |
| `build_session()` | 创建带固定 UA / Accept 的 `requests.Session` |
| `ajax_headers(referer)` | 构造仿浏览器的 AJAX 请求头（origin/referer/x-requested-with） |
| `login(session, email, password)` | 完整登录流程：开登录页 → 求解验证码 → POST 带完整浏览器字段；处理 405 自动切换、`ret`/`phase` 判定 |
| `checkin(session)` | POST `/user/checkin`，解析返回并提取纯文本 msg |
| `solve_captcha()` | 调用 `geeked.Geeked` 求解 GeeTest V4，含 `MAX_CAPTCHA_RETRIES` 重试 |
| `extract_traffic_reward(message)` | 从“签到成功，共 xxx GB 流量”中正则提取奖励数值 |

### 4.6 签到编排层

**`sign_one(index, email, password)`** 是单账号签到的核心编排函数，遵循 README 中描述的判定规则：

```text
登录失败          → 直接返回失败（不执行签到）
登录成功 → 主页已签到 → 返回成功（stage="已签到"）
登录成功 → 主页可签到 → 执行 checkin → 签到后主页再验证：
    后 signed   → 成功（stage="签到并验证"）
    后 unsigned → 失败（stage="签到验证失败"，证据冲突）
    后 unknown + 接口 ret=1 → 成功（stage="签到成功（接口确认）"），推送注明主页暂未确认
    后 unknown + 接口非成功 → 失败（stage="签到待确认"），避免误报
```

### 4.7 通知层

| 函数 | 职责 |
| --- | --- |
| `build_notification(results)` | 汇总所有账号结果，生成 4 元组：`title` + 纯文本 + Markdown + 响应式 HTML |
| `send_serverchan(title, content)` | Server酱推送（Markdown 分段），校验 `code==0` |
| `send_email(title, content, html)` | **邮件投递策略总控**，GHA 环境优先 Resend，本地优先 SMTP，失败自动 fallback |
| `send_email_resend(...)` | Resend HTTPS 发信（绕过 GHA SMTP 端口封锁），含 403 测试发件人友好提示 |
| `send_email_smtp(...)` | SMTP 发信，含 SSL/STARTTLS 自动 fallback 尝试 |
| `_smtp_error_message(exc)` | 将 SMTP/网络异常分类为人类可读中文提示 |
| `notify(title, plain, md, html)` | 汇总调用 Server酱 + 邮件，打印投递报告 |

---

## 5. 关键类与函数说明

### 5.1 `main()` — 程序入口

```python
def main() -> int:
```

- 解析 `URL` 并探测可用面板，写入全局 `BASE_URL`
- 解析 `CONFIG` 多账号（偶数行：邮箱/密码交替）
- 逐账号调用 `sign_one`，异常时降级为 `AccountResult(ok=False, stage="程序异常")`
- 汇总结果 → `build_notification` → `notify`
- **退出码语义**：
  - `0`：全部账号签到成功
  - `1`：`CONFIG` 缺失或格式错误
  - `2`：存在账号签到失败
  - `3`：开启 `REQUIRE_NOTIFICATION_SUCCESS` 且无通知渠道成功

### 5.2 `login()` — 登录与验证码集成

关键点：
- 先 GET 登录页（保持 cookie）
- 调用 `solve_captcha()` 获取 `lot_number` / `captcha_output` / `pass_token` / `gen_time`
- POST payload 中补齐 `host` / `pageLoadedAt` / 嵌套的 `captcha_result[...]` 字段（仿浏览器）
- 依据 `ret`（1=成功，2=需 2FA）与 `phase`（`reset_login`=验证被拒）判定

### 5.3 `sign_one()` — 签到结果可信判定

这是“为什么签到结果可信”的核心实现。详细规则见 [README.md:192-207](file:///e:/Other/Github/jichang_checkin-main/README.md#L192-L207)，代码实现于 [main.py:992-1064](file:///e:/Other/Github/jichang_checkin-main/main.py#L992-L1064)。

### 5.4 `send_email()` — 通知策略总控

环境感知的邮件投递策略：

| 环境 | SMTP 配置 | Resend 配置 | 策略 |
| --- | --- | --- | --- |
| GHA | 有 | 有 | 先 Resend，成功即返回；失败 fallback SMTP |
| GHA | 有 | 无 | SMTP（带 SSL/STARTTLS fallback） |
| GHA | 无 | 有 | Resend |
| 本地 | 有 | 有 | 先 SMTP，失败 fallback Resend |
| 本地 | 有 | 无 | SMTP |

---

## 6. 依赖关系

### 6.1 Python 依赖（requirements.txt）

| 依赖 | 版本 | 用途 |
| --- | --- | --- |
| `requests` | 2.32.5 | HTTP 客户端，登录/签到/通知全链路 |
| `curl_cffi` | 0.10.0 | GeekedTest 依赖，用于 TLS 指纹模拟 |
| `pycryptodome` | 3.21.0 | GeekedTest 依赖，加解密 |

### 6.2 运行时 vendoring 依赖

- **GeekedTest**（`geeked` 包）：在 GitHub Actions 中通过固定 commit `93a81933...` vendoring，并**移除** `SlideSolver` / `GobangSolver` / `IconSolver` 等需要图像处理的子求解器（仅保留 `Geeked.solve()` 主流程）。

### 6.3 标准库依赖（无安装成本）

`base64`, `json`, `os`, `re`, `socket`, `smtplib`, `ssl`, `time`, `dataclasses`, `datetime`, `email.mime`, `html`, `html.parser`, `typing`, `urllib.parse`, `zoneinfo`

### 6.4 模块内调用关系

```text
main
 └─ resolve_base_url ── probe_panel_api
 └─ parse_accounts
 └─ sign_one
      ├─ build_session
      ├─ login
      │    ├─ solve_captcha (→ geeked.Geeked)
      │    └─ ajax_headers
      ├─ inspect_dashboard
      │    ├─ unwrap_origin_body
      │    └─ parse_dashboard_state ── _DashboardParser
      ├─ checkin
      ├─ extract_traffic_reward
      └─ AccountResult
 └─ build_notification
 └─ notify
      ├─ send_serverchan
      └─ send_email
           ├─ send_email_resend
           └─ send_email_smtp ── _smtp_error_message
```

---

## 7. 项目运行方式

### 7.1 GitHub Actions 部署（推荐）

工作流定义见 [.github/workflows/main.yml](file:///e:/Other/Github/jichang_checkin-main/.github/workflows/main.yml)。

**触发方式：**
- 定时：`cron: "10 16 * * *"`（UTC 16:10 = 北京时间 00:10），并加 10–180 秒随机抖动避免整点拥堵
- 手动：`workflow_dispatch`

**执行步骤：**
1. Checkout（固定 actions 版本 SHA，避免供应链风险）
2. 安装 Python 3.10
3. 随机 sleep（仅定时触发）
4. 安装依赖 `pip install -r requirements.txt`
5. **运行离线测试** `python -B -m unittest discover -s tests -v`
6. **Vendor GeekedTest**：拉取固定 commit，剥离图像求解器 import
7. 运行 `python main.py`，注入所有 Secrets 作为环境变量

### 7.2 本地运行

```bash
pip install -r requirements.txt
# 准备 geeked 包（按 workflow 方式 vendoring 或手动放置）
export URL=https://ikuuu.win
export CONFIG=$'email@example.com\npassword'
python main.py
```

### 7.3 运行测试

```bash
python -B -m unittest discover -s tests -v
```

测试覆盖（见 [tests/test_main.py](file:///e:/Other/Github/jichang_checkin-main/tests/test_main.py)）：
- `DashboardStateTests`：主页签到状态判定（含 Base64 包裹、各种模板）
- `CheckinDecisionTests`：签到决策逻辑（已签到跳过、接口与主页冲突判定、流量奖励提取）
- `SmtpConfigurationTests`：SMTP 配置合并（独立变量覆盖分组变量）
- `NotificationTests`：通知策略（GHA fallback、Resend 投递、Server酱 code 校验、多格式内容生成）

### 7.4 配置项速查

**必填 Secret：**

| Secret | 说明 |
| --- | --- |
| `CONFIG` | 一行邮箱一行密码，可多组 |

**可选 Secret / Variable：**

| 名 | 类型 | 说明 | 默认 |
| --- | --- | --- | --- |
| `URL` | Secret | 面板地址（勿填公告页 `ikuuu.co`） | `https://ikuuu.win` |
| `SCKEY` | Secret | Server酱 SendKey | 空 |
| `CAPTCHA_ID` | Secret | GeeTest captchaId | ikuuu 当前值 |
| `CAPTCHA_RISK_TYPE` | Secret | 验证码类型 | `ai` |
| `SMTP_SERVER` / `SMTP_ACCOUNT` | Secret | 分组式 SMTP 配置 | 空 |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `SMTP_TO` / `SMTP_FROM` | Secret | Newapi-checkin 兼容独立变量（优先级更高） | 空 |
| `MAIL_TO` | Secret | 邮件收件人（逗号分隔多个） | SMTP_ACCOUNT 第三行或发件账号 |
| `RESEND_API_KEY` | Secret | Resend HTTPS 发信 | 空 |
| `RESEND_FROM` | Secret | Resend 发件人（需已验证域名） | `onboarding@resend.dev` |
| `CHECKIN_TIMEZONE` | Variable | 判断“今天”的 IANA 时区 | `Asia/Shanghai` |
| `REQUIRE_NOTIFICATION_SUCCESS` | Variable | 所有通知失败时让任务退出失败 | `false` |

### 7.5 网页配置工具

项目内置两个纯前端 HTML 工具，用于辅助部署：

| 文件 | 职责 |
| --- | --- |
| [index.html](file:///e:/Other/Github/jichang_checkin-main/index.html) | 落地页，通过 `meta refresh` + `window.location.replace` 即时跳转到配置生成器 |
| [config_generator.html](file:///e:/Other/Github/jichang_checkin-main/config_generator.html) | 配置生成器：表单填写 → 生成各 Secret 值 → 一键复制 + 跳转 GitHub Secrets 页 |

**配置生成器核心功能：**

- **多账号动态表单**：动态增删账号行，一行邮箱一行密码，对应 `CONFIG` 格式
- **可折叠高级配置**：Server 酱、SMTP、Resend、MAIL_TO、Captcha ID、时区
- **逐项 Secret 输出**：为 `CONFIG` / `URL` / `SCKEY` / `SMTP_SERVER` / `SMTP_ACCOUNT` / `MAIL_TO` / `RESEND_API_KEY` / `RESEND_FROM` / `CAPTCHA_ID` 分别生成带「复制」按钮的卡片
- **一键跳转 GitHub Secrets**：输入 `owner/repo`，跳转到 `https://github.com/{owner}/{repo}/settings/secrets/actions`
- **本地持久化**：所有输入实时保存到 `localStorage`，刷新不丢失；数据仅在浏览器本地处理，不上传任何服务器

**访问方式：**
- 本地：双击 `index.html`（自动跳转）或直接打开 `config_generator.html`
- 在线：通过 GitHub Pages 托管后访问

---

## 8. 设计要点与安全说明

### 8.1 可信判定哲学

项目反复强调“不因 `ret=1` 或文案含‘已签到/流量’就报成功”。`sign_one` 通过**接口事务结果 × 主页状态**的二维交叉验证实现可信判定，五个退出分支分别对应 README 中的判定规则。

### 8.2 URL 探测机制

`ikuuu.co` 是域名公告页，仅用于查询当前可用域名，**不提供** SSPanel API。若误配，`/auth/login` 会返回 nginx `405`。`resolve_base_url` 通过 `probe_panel_api` 主动探测，命中 405 或非 JSON 响应时自动切换到 `PANEL_CANDIDATES`。

### 8.3 GitHub Actions 网络适配

- GHA 托管 Runner 常封锁 SMTP 25/465/587 出站端口
- `send_email` 检测 `GITHUB_ACTIONS=true`，优先 Resend HTTPS
- SMTP 日志将 host/port 分开打印，避免 Secret 打码把 `smtp.qq.com:465` 变成误导性的 `***`

### 8.4 安全实践

- 所有账号在日志与通知中经 `mask_account` 脱敏
- GitHub Actions 使用固定 SHA pinning（`actions/checkout@fbc6f399...`、`actions/setup-python@ece7cb06...`）防供应链攻击
- GeekedTest 固定 commit，不直接执行上游最新分支
- Secret 全部经环境变量注入，不入库
- `unwrap_origin_body` 对 Base64 包裹层设 8MB 上限，防资源耗尽

---

## 9. 扩展指引

- **支持 2FA**：当前 `login` 中 `twofa_step=0`，若开启 2FA 需扩展 TOTP 生成
- **新增机场**：调整 `DEFAULT_URL` / `CAPTCHA_ID` / `DIRECTORY_HOSTS` / `PANEL_CANDIDATES`
- **新增通知渠道**：实现返回 `DeliveryResult` 的 `send_xxx()`，并在 `notify` 中加入调用
- **主页模板适配**：`parse_dashboard_state` 的 `signed_markers` 与控件文案匹配规则可按需扩展，并补充对应测试用例

---

*本文档基于仓库当前代码状态生成，代码位置链接指向本地绝对路径，便于在编辑器中直接跳转。*
