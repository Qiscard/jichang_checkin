# ikuuu 自动签到

GitHub Actions 定时签到脚本，支持 GeeTest V4 验证码自动求解、多账号、Server 酱推送。

## 功能

- **自动登录**：邮箱 + 密码登录，自动求解 GeeTest V4 验证码
- **验证码求解**：内置 icon（ONNX 模型分类）+ word（OCR 识别）双引擎
- **自动签到**：登录后 POST 签到，并回验主页确认签到状态
- **多账号**：支持同时签到多个 ikuuu 账号
- **域名自适应**：ikuuu 频繁更换域名，脚本自动探测最新可用面板地址
- **TLS 指纹**：使用 curl_cffi 模拟 Chrome TLS 指纹，绕过服务端 TLS 拦截
- **Server 酱推送**：签到结果通过 Server 酱推送到微信

## 快速开始

### 1. Fork 本仓库

### 2. 配置 Secrets

在仓库 **Settings → Secrets and variables → Actions → Secrets** 中添加：

| Secret | 必填 | 说明 |
|--------|------|------|
| `CONFIG` | ✅ | 账号配置，多账号用换行分隔，每行格式：`邮箱----密码` |
| `SCKEY` | ❌ | Server 酱推送密钥，不填则不推送 |
| `URL` | ❌ | 面板地址，不填自动探测（默认 `https://ikuuu.foo`） |
| `CAPTCHA_ID` | ❌ | GeeTest 验证码 ID，默认 `cc96d05ba8b60f9112f76e18526fcb73` |
| `CAPTCHA_RISK_TYPE` | ❌ | 验证码类型，默认 `ai` |

#### CONFIG 格式

```
user1@email.com----password1
user2@email.com----password2
```

#### Server 酱配置

1. 访问 [sct.ftqq.com](https://sct.ftqq.com/) 注册并获取 SendKey
2. 将 SendKey 填入 `SCKEY` Secret

### 3. 运行

仓库已配置 GitHub Actions 定时任务（每天北京时间 00:10 自动执行），也可在 **Actions** 页面手动触发。

## 本地运行

```bash
pip install -r requirements.txt

export CONFIG="your_email----your_password"
export SCKEY="your_serverchan_key"  # 可选

python main.py
```

## 配置生成器

打开 [`config_generator.html`](config_generator.html) 可在线生成 CONFIG 格式，复制即用。

## 技术细节

### GeeTest V4 验证码求解

ikuuu 的 GeeTest V4 配置为 `risk_type=ai` + 自适应模式，验证流程为：

1. **第一次 verify**（ai 无感验证）→ 返回 `result=continue`
2. **第二次 load** → 升级为 `icon`/`word` 图片验证码
3. **图片验证码求解**：
   - `icon` 类型：用 `geetest_v4_icon.onnx` 模型分类图标（对象_方向）
   - `word` 类型：用 `ddddocr` OCR 识别文字
4. **第二次 verify**（带 userresponse 点击坐标）→ 返回 `result=success`

### 登录流程

ikuuu 新版登录采用 `phase` 多阶段机制：

```
POST /auth/login
  phase=password
  email=xxx
  passwd=xxx
  captcha_result[lot_number]=xxx
  captcha_result[captcha_output]=xxx
  captcha_result[pass_token]=xxx
  captcha_result[gen_time]=xxx
```

成功返回 `{"result":"authenticated","msg":"登录成功"}`。

### 域名轮换

ikuuu 定期更换面板域名（旧域名会被和谐）。脚本通过以下方式自适应：

1. 访问公告页 `ikuuu.li` 获取最新域名列表
2. 逐个探测域名是否为有效面板（POST `/auth/login` 探测）
3. 当前已知面板域名：`ikuuu.foo`、`ikuuu.bar`

## 文件说明

| 文件 | 说明 |
|------|------|
| `main.py` | 主脚本，包含登录、验证码求解、签到、推送全部逻辑 |
| `geetest_v4_icon.onnx` | GeeTest V4 图标分类 ONNX 模型 |
| `charsets.json` | 图标分类标签集 |
| `requirements.txt` | Python 依赖 |
| `.github/workflows/main.yml` | GitHub Actions 定时任务 |
| `config_generator.html` | 在线配置生成器 |
| `tests/test_main.py` | 单元测试 |

## 依赖

- `requests` — HTTP 请求
- `pycryptodome` — GeeTest V4 加密
- `curl_cffi` — Chrome TLS 指纹模拟
- `ddddocr` — 验证码 OCR / 图标分类
- `onnxruntime` — ONNX 模型推理
- `opencv-python-headless` — 图像处理
