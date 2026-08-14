# 机场自动签到（优化版）

适用于 **SSPanel** 机场（已针对 https://ikuuu.win / https://ikuuu.co 验证）。

## 你遇到的问题

推送内容：

> 验证失败：系统无法接受您的验证结果，请刷新页面后重试。

对应服务端返回：

```json
{"ret":0,"msg":"系统无法接受您的验证结果，请刷新页面后重试。","phase":"reset_login"}
```

结论：

1. ikuuu 登录强制 GeeTest V4 验证码
2. 旧脚本只提交邮箱密码，没有有效 captcha_result
3. 登录被拒绝后，旧脚本不会真正执行签到
4. 网页上看到“已签到/有流量”，通常来自浏览器手动登录、当天更早成功签到，或其他入口，而不是这次失败的 Actions

## 本版改动

- 接入 GeeTest V4 自动求解（GeekedTest）
- 登录请求补齐浏览器字段：host / pageLoadedAt / captcha_result
- 阶段化结果：登录、签到接口、主页验证分开报告
- 签到后重新读取账户主页，综合接口 `ret` 与页面状态交叉验证
- 登录失败不再继续签到
- 支持 Server酱 + SMTP / Resend 邮件推送，并检查实际投递结果
- 兼容 `Newapi-checkin` 的独立 SMTP Secrets，无需重复改名已有配置
- Server酱使用 Markdown 分段排版，邮件同时发送纯文本和响应式 HTML
- 首次签到会提取接口返回的流量奖励，并在各类推送中单独展示
- URL 可配置，默认 https://ikuuu.win
- Actions 依赖与 workflow 同步修正

## URL 重要说明

- `https://ikuuu.co` 是**域名公告页**，只用于查询当前可用域名，**不能**作为签到 `URL`
- 签到 `URL` 必须是用户面板域名，例如：`https://ikuuu.win`
- 若误配成 `ikuuu.co`，登录 POST 会返回 nginx `405 Not Allowed`
- 本脚本会自动探测：发现目录页/405 时回退到可用面板（默认 `https://ikuuu.win`）

推荐：

```text
URL=https://ikuuu.win
```

或直接不填 `URL`（默认就是 `https://ikuuu.win`）。

## 部署

> 💡 **推荐**：使用仓库自带的 [网页配置生成器](config_generator.html)（双击打开 `config_generator.html` 或通过 GitHub Pages 访问），图形化填写账号与通知参数，自动生成各 Secret 的值，并提供「一键跳转 GitHub Secrets」按钮，免去手动拼接文本。
>
> 部署流程：
> 1. 打开 `config_generator.html`（或经 `index.html` 自动跳转进入）
> 2. 填写机场账号、密码及可选通知参数 → 点击「生成配置」
> 3. 点击每个 Secret 右侧的「复制」按钮，再点「跳转 GitHub Secrets」直达仓库设置页逐项粘贴
> 4. 在 Actions 中手动运行一次 `Airport Checkin`，此后每日自动执行

1. 使用本仓库代码（或覆盖你 fork 中的文件）
2. Settings -> Secrets and variables -> Actions 配置密钥
3. Actions 中手动运行 `Airport Checkin`

### 必填

| Secret | 说明 |
| --- | --- |
| CONFIG | 一行邮箱一行密码，可多组 |

### 可选

| Secret | 说明 | 默认 |
| --- | --- | --- |
| URL | 面板地址（不要填 ikuuu.co 公告页） | https://ikuuu.win |
| SCKEY | Server酱 SendKey | 空 |
| CAPTCHA_ID | GeeTest captchaId | ikuuu 当前值 |
| CAPTCHA_RISK_TYPE | 验证码类型 | ai |
| SMTP_SERVER | SMTP 主机+端口（可带 ssl/starttls） | 空 |
| SMTP_ACCOUNT | SMTP 账号：用户/授权码，可兼容第三行收件人 | 空 |
| SMTP_HOST | SMTP 主机，兼容 Newapi-checkin | 空 |
| SMTP_PORT | SMTP 端口，兼容 Newapi-checkin；465=SSL，587=STARTTLS | 465 |
| SMTP_USER | SMTP 登录账号，兼容 Newapi-checkin | 空 |
| SMTP_PASS | SMTP 授权码，兼容 Newapi-checkin | 空 |
| SMTP_TO | SMTP 收件人，兼容 Newapi-checkin | 空 |
| SMTP_FROM | SMTP 发件人，兼容 Newapi-checkin | SMTP_USER |
| MAIL_TO | 邮件收件人，多个地址用英文逗号分隔 | SMTP_ACCOUNT 第三行或发件账号 |
| RESEND_API_KEY | Resend HTTPS 发信（推荐用于 GitHub Actions） | 空 |
| RESEND_FROM | Resend 发件人（需已验证域名；可空） | onboarding@resend.dev |

可选的 Actions Variables：

| Variable | 说明 | 默认 |
| --- | --- | --- |
| CHECKIN_TIMEZONE | 用于判断“今天”的 IANA 时区 | Asia/Shanghai |
| REQUIRE_NOTIFICATION_SUCCESS | 所有已配置通知均失败时，让任务退出失败 | false |

### 邮件 Secrets 示例（QQ 邮箱）

如果另一个 `Newapi-checkin` 工作流已经能正常发信，可直接复用同名配置：

```text
SMTP_HOST=smtp.qq.com
SMTP_PORT=465
SMTP_USER=你的QQ邮箱
SMTP_PASS=QQ邮箱授权码
SMTP_TO=接收邮箱
SMTP_FROM=你的QQ邮箱
```

独立变量优先于下方的组合变量。`SMTP_FROM` 可不填，默认使用 `SMTP_USER`。
组合配置继续保留，适合只想维护两个 Secret 的用户。

`SMTP_SERVER`（主机+端口一组）：

```text
smtp.qq.com:465
```

也支持两行：

```text
smtp.qq.com
465
```

`587` 默认走 STARTTLS；`465` 默认走 SSL。可显式写：

```text
smtp.qq.com:587:starttls
```

`SMTP_ACCOUNT`（用户/授权码）：

```text
你的QQ邮箱
授权码
```

`MAIL_TO`：

```text
接收邮箱
```

旧配置仍兼容在 `SMTP_ACCOUNT` 第三行填写收件人，也支持单行
`你的QQ邮箱;授权码;接收邮箱`。

### 关于 GitHub Actions 邮件失败

如果你配置了：

```text
SMTP_SERVER=smtp.qq.com:465
```

但日志出现：

```text
[push] Email attempt failed: ***/SSL: Connection unexpectedly closed
```

说明：

1. `***` 是 GitHub 把 Secret 原文 `smtp.qq.com:465` 打码后的结果，**不是主机丢了**
2. 你的 QQ 邮箱 SMTP 填写通常是对的
3. GitHub 托管 Runner 的 SMTP 网络可用性不稳定，连接可能在认证前被断开
4. 新版会将认证失败、收件人拒绝、超时、网络错误和 TLS 错误分别写入投递报告

可选方案：

A. **继续用 Server酱**（你已经 `status=200`，可先靠它收通知）  
B. **Actions 上改用 Resend HTTPS 发信**（推荐）  
C. 自建 Runner 再继续用 QQ SMTP

#### Resend 配置示例

1. 注册 https://resend.com 并创建 API Key  
2. Secrets 增加：

```text
RESEND_API_KEY=re_xxx
MAIL_TO=接收邮箱
```

使用默认测试发件人 `onboarding@resend.dev` 时，Resend **只能发送到注册
Resend 的账号邮箱**。因此首次测试应将 `MAIL_TO` 设置为该邮箱，`RESEND_FROM`
保持为空。

如果要发送到 Gmail 等其他地址，需要先在 Resend 验证自己的域名，然后增加：

```text
RESEND_FROM=通知 <notice@你验证过的域名>
```

仅设置一个未经验证的 `RESEND_FROM` 不能解除 403 限制。

### 签到结果为什么可信

脚本不会因为 `ret=0` 响应文本中包含“已签到”“流量”或任意非空消息就报成功。每个账号会：

1. 登录后读取 `/user`，确认会话有效并记录签到控件状态
2. 调用 `/user/checkin`
3. 再次读取 `/user`
4. 综合接口事务结果与主页状态作出判断，并提取“签到成功，共 xxx 流量”中的奖励

判定规则：

- 接口 `ret=1`，主页已签到：成功，双重确认
- 接口 `ret=1`，主页状态未知：成功，但推送会注明主页暂未确认
- 接口 `ret=1`，主页仍明确可签到：证据冲突，按失败处理
- 接口 `ret=0` 且仅提示“已经签到过”，主页状态未知：仍按失败处理，避免误报
- 无论接口返回什么，只要主页明确显示今日已签到：成功

## 本地运行

```bash
pip install -r requirements.txt
# 按 workflow 方式准备 ./geeked
export URL=https://ikuuu.win
export CONFIG=$'email@example.com\npassword'
python main.py
```

## 说明

- 验证码求解依赖社区项目 https://github.com/xKiian/GeekedTest
- Actions 固定使用经过检查的 GeekedTest commit，不会每次直接执行上游最新分支
- 若开启 2FA，需要先关闭或自行扩展 TOTP
- 请遵守机场服务条款，仅用于个人账号
