import requests
import json
import re
import os
from urllib.parse import quote

# 机场地址
BASE_URL = 'https://ikuuu.win'
LOGIN_URL = f'{BASE_URL}/auth/login'
CHECKIN_URL = f'{BASE_URL}/user/checkin'

# 读取环境变量
CONFIG = os.environ.get('CONFIG', '')
SCKEY = os.environ.get('SCKEY', '')

# 提取响应里的JSON字符串
def extract_json(text: str):
    match = re.search(r'\{.*?\}', text, re.S)
    if not match:
        return None
    try:
        return json.loads(match.group())
    except:
        return None

# 消息推送封装
def send_push(title: str, desp: str):
    if not SCKEY:
        return
    desp_encode = quote(desp)
    push_api = f'https://sctapi.ftqq.com/{SCKEY}.send?title={quote(title)}&desp={desp_encode}'
    try:
        requests.post(push_api, timeout=10)
        print("推送成功")
    except Exception as e:
        print(f"推送失败：{str(e)}")

def sign(order, user, pwd):
    session = requests.Session()
    headers = {
        'origin': BASE_URL,
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'
    }
    login_data = {
        'email': user,
        'passwd': pwd
    }
    content = ""
    try:
        print(f'===账号{order}进行登录...===')
        print(f'账号：{user}')
        # 登录请求，设置超时防止卡死
        resp_text = session.post(
            url=LOGIN_URL,
            headers=headers,
            data=login_data,
            timeout=15
        ).text
        # 提取json
        login_json = extract_json(resp_text)
        if not login_json:
            raise Exception("登录接口未返回有效JSON，验证拦截返回HTML页面")

        login_msg = login_json.get("msg", "无提示信息")
        print("登录返回消息：", login_msg)

        # 判断验证失败，直接抛出异常终止签到
        if login_json.get("ret") == 0 and login_json.get("phase") == "reset_login":
            raise Exception(f"验证失败：{login_msg}")

        # 登录成功执行签到
        checkin_resp = session.post(
            url=CHECKIN_URL,
            headers=headers,
            timeout=15
        ).text
        checkin_json = extract_json(checkin_resp)
        if not checkin_json:
            raise Exception("签到接口无有效返回数据")

        content = checkin_json.get("msg", "签到完成")
        print("签到结果：", content)

    except Exception as ex:
        content = f"签到失败，异常信息：{str(ex)}"
        print(content)
    # 统一推送结果
    send_push(title="IKUUU机场签到通知", desp=f"账号{order}({user})\n{content}")
    print(f'===账号{order}签到结束===\n')

if __name__ == '__main__':
    if not CONFIG:
        print("环境变量CONFIG未配置！")
        exit(1)
    config_lines = [line.strip() for line in CONFIG.splitlines() if line.strip()]
    if len(config_lines) % 2 != 0 or len(config_lines) == 0:
        print('CONFIG配置格式错误，格式：一行邮箱一行密码交替')
        exit(1)
    account_count = len(config_lines) // 2
    for idx in range(account_count):
        email = config_lines[idx * 2]
        password = config_lines[idx * 2 + 1]
        sign(idx, email, password)
