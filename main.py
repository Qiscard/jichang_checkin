#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSPanel airport daily check-in script (GeeTest V4 + notify)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import random
import re
import socket
import smtplib
import ssl
import time
from dataclasses import dataclass
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote_plus
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey.RSA import construct
from Crypto.Util.Padding import pad

DEFAULT_URL = "https://ikuuu.win"
DEFAULT_CAPTCHA_ID = "cc96d05ba8b60f9112f76e18526fcb73"
DEFAULT_RISK_TYPE = "ai"
# Domain bulletin / mirror list pages that do NOT provide SSPanel APIs.
DIRECTORY_HOSTS = {
    "ikuuu.co",
    "www.ikuuu.co",
    "ikuuu.de",
    "www.ikuuu.de",
    "ikuuu.org",
    "www.ikuuu.org",
    "ikuuu.ch",
    "www.ikuuu.ch",
}
# Domain directory page that publishes the latest available panel domains.
DOMAIN_DIRECTORY_URL = "https://ikuuu.de/"
# Known panel hosts used as fallback when discovery fails or configured URL
# is a directory page / returns 405. Extended at runtime with discovered hosts.
# ikuuu periodically rotates panel domains (win/fyi/eu/pw/...); list every
# known panel host so the script keeps working when discovery is unavailable.
PANEL_CANDIDATES = [
    "https://ikuuu.win",
    "https://ikuuu.fyi",
    "https://ikuuu.eu",
    "https://ikuuu.pw",
    "https://ikuuu.one",
]
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
MAX_CAPTCHA_RETRIES = 3
MAX_CHECKIN_RETRIES = 5
REQUEST_TIMEOUT = 20


def env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


CAPTCHA_ID = env("CAPTCHA_ID", DEFAULT_CAPTCHA_ID)
CAPTCHA_RISK_TYPE = env("CAPTCHA_RISK_TYPE", DEFAULT_RISK_TYPE)
CONFIG = env("CONFIG")
SCKEY = env("SCKEY")
URL_RAW = env("URL", DEFAULT_URL)

# Grouped mail secrets:
#   SMTP_SERVER  -> host + port  (e.g. smtp.qq.com:465  or two lines)
#   SMTP_ACCOUNT -> user / pass / mail_to  (three lines; mail_to optional)
SMTP_SERVER = env("SMTP_SERVER")
SMTP_ACCOUNT = env("SMTP_ACCOUNT")
# Newapi-checkin-compatible individual secrets. When present, these override
# the corresponding grouped values above so an existing Actions setup works.
SMTP_HOST_ENV = env("SMTP_HOST")
SMTP_PORT_ENV = env("SMTP_PORT")
SMTP_USER_ENV = env("SMTP_USER")
SMTP_PASS_ENV = env("SMTP_PASS")
SMTP_TO_ENV = env("SMTP_TO")
SMTP_FROM_ENV = env("SMTP_FROM")
RESEND_API_KEY = env("RESEND_API_KEY")
RESEND_FROM = env("RESEND_FROM")  # optional; must belong to a Resend-verified domain
MAIL_TO_ENV = env("MAIL_TO")
CHECKIN_TIMEZONE = env("CHECKIN_TIMEZONE", "Asia/Shanghai")
REQUIRE_NOTIFICATION_SUCCESS = env("REQUIRE_NOTIFICATION_SUCCESS").lower() in {
    "1",
    "true",
    "yes",
}

# Resolved at runtime by resolve_base_url()
BASE_URL = DEFAULT_URL


def parse_smtp_server(raw: str) -> tuple[str, int, bool]:
    """Parse host/port[/ssl] from one secret."""
    raw = (raw or "").strip()
    if not raw:
        return "", 465, True

    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if len(lines) >= 2 and ":" not in lines[0]:
        host = lines[0]
        port_part = lines[1]
        mode = lines[2] if len(lines) >= 3 else ""
    else:
        parts = re.split(r"[:\s]+", lines[0])
        if len(parts) == 1:
            host, port_part, mode = parts[0], "465", ""
        elif len(parts) == 2:
            host, port_part, mode = parts[0], parts[1], ""
        else:
            host, port_part, mode = parts[0], parts[1], parts[2]

    try:
        port = int(port_part)
    except Exception:
        port = 465

    mode_l = (mode or "").strip().lower()
    if mode_l in {"starttls", "tls", "0", "false", "no"}:
        use_ssl = False
    elif mode_l in {"ssl", "1", "true", "yes"}:
        use_ssl = True
    else:
        use_ssl = port != 587
    return host, port, use_ssl


def parse_smtp_account(raw: str) -> tuple[str, str, str]:
    """Parse user/pass/mail_to from one secret."""
    raw = (raw or "").strip()
    if not raw:
        return "", "", ""

    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if len(lines) == 1:
        parts = [p.strip() for p in re.split(r"[;,|]", lines[0]) if p.strip()]
    else:
        parts = lines

    user = parts[0] if len(parts) >= 1 else ""
    password = parts[1] if len(parts) >= 2 else ""
    mail_to = parts[2] if len(parts) >= 3 else user
    return user, password, mail_to


def resolve_smtp_config() -> tuple[str, int, bool, str, str, str, str]:
    grouped_host, grouped_port, grouped_ssl = parse_smtp_server(SMTP_SERVER)
    grouped_user, grouped_pass, grouped_to = parse_smtp_account(SMTP_ACCOUNT)

    host = SMTP_HOST_ENV or grouped_host
    port = grouped_port
    use_ssl = grouped_ssl
    if SMTP_PORT_ENV:
        try:
            port = int(SMTP_PORT_ENV)
        except ValueError:
            port = grouped_port
        use_ssl = port != 587

    user = SMTP_USER_ENV or grouped_user
    password = SMTP_PASS_ENV or grouped_pass
    mail_to = SMTP_TO_ENV or MAIL_TO_ENV or grouped_to or user
    mail_from = SMTP_FROM_ENV or user
    return host, port, use_ssl, user, password, mail_to, mail_from


SMTP_HOST, SMTP_PORT, SMTP_SSL, SMTP_USER, SMTP_PASS, MAIL_TO, MAIL_FROM = resolve_smtp_config()


def parse_json_loose(text: str) -> Optional[dict]:
    text = (text or "").strip()
    if not text:
        return None
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except Exception:
        pass
    matches = re.findall(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.S)
    for raw in reversed(matches):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
        except Exception:
            continue
    return None


def host_from_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return (parsed.netloc or "ikuuu.win").lower()


# Hosts that should never be treated as real SSPanel panels even if they appear
# on the directory page (announcements, CDN placeholders, doc sites, ...).
_NON_PANEL_HOSTS = {
    "ikuuu.de",
    "www.ikuuu.de",
    "ikuuu.co",
    "www.ikuuu.co",
    "ikuuu.org",
    "www.ikuuu.org",
    "ikuuu.ch",
    "www.ikuuu.ch",
}


def discover_panel_hosts() -> List[str]:
    """Fetch https://ikuuu.de/ and extract candidate panel domains.

    The directory page lists the current available domain(s) as links such as
    ``https://ikuuu.win/``. We collect every ikuuu-like host, strip the scheme,
    and return them ordered by appearance. Discovery never raises: on any error
    it returns an empty list so callers can fall back to PANEL_CANDIDATES.
    """
    discovered: List[str] = []
    try:
        resp = requests.get(
            DOMAIN_DIRECTORY_URL,
            headers={"user-agent": UA, "accept": "text/html,*/*"},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
    except Exception as exc:
        print(f"[url] discover {DOMAIN_DIRECTORY_URL} failed: {exc}")
        return discovered

    if resp.status_code >= 400:
        print(f"[url] discover {DOMAIN_DIRECTORY_URL} -> HTTP {resp.status_code}")
        return discovered

    html = resp.text or ""
    # Prefer real <a href> links, then any ikuuu.* host substring as a fallback.
    seen = set()
    for match in re.finditer(r'href\s*=\s*["\']([^"\']+)["\']', html, re.I):
        link = match.group(1).strip()
        if not link or link.startswith("#"):
            continue
        host = host_from_url(link)
        if host in seen or host in _NON_PANEL_HOSTS:
            continue
        if "ikuuu" not in host:
            continue
        seen.add(host)
        discovered.append(f"https://{host}")

    if not discovered:
        for match in re.finditer(r"\b(?:https?://)?([a-z0-9.-]*ikuuu[a-z0-9.-]+)", html, re.I):
            host = match.group(1).strip(".").lower()
            if host in seen or host in _NON_PANEL_HOSTS:
                continue
            seen.add(host)
            discovered.append(f"https://{host}")

    print(f"[url] discovered panel hosts from directory: {discovered}")
    return discovered


def normalize_base_url(url: str) -> str:
    """Keep only scheme://host, drop /user /auth/login etc."""
    url = (url or "").strip()
    if not url:
        url = DEFAULT_URL
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc
    if not netloc and parsed.path:
        # handle values like ikuuu.win/user
        netloc = parsed.path.split("/")[0]
    return f"{scheme}://{netloc}".rstrip("/")


def mask_account(account: str) -> str:
    if "@" not in account:
        return account[:2] + "***" if len(account) > 2 else "***"
    name, domain = account.split("@", 1)
    if len(name) <= 2:
        masked = name[:1] + "***"
    else:
        masked = name[:2] + "***" + name[-1:]
    return f"{masked}@{domain}"


def probe_panel_api(base: str) -> Tuple[bool, str]:
    """Return whether base looks like a real SSPanel login API."""
    base = normalize_base_url(base)
    url = f"{base}/auth/login"
    try:
        resp = requests.post(
            url,
            headers={
                "user-agent": UA,
                "origin": base,
                "referer": f"{base}/auth/login",
                "x-requested-with": "XMLHttpRequest",
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                "accept": "application/json, text/javascript, */*; q=0.01",
            },
            data={
                "email": "panel-probe@example.com",
                "passwd": "probe",
                "code": "",
                "twofa_step": 0,
                "pageLoadedAt": str(int(time.time() * 1000)),
            },
            timeout=12,
            allow_redirects=False,
        )
    except Exception as exc:
        return False, f"request failed: {exc}"

    if resp.status_code == 405:
        return (
            False,
            "405 Not Allowed - this host is NOT the user panel API "
            "(common when URL is set to domain bulletin page like ikuuu.co)",
        )

    data = parse_json_loose(resp.text)
    if isinstance(data, dict) and ("ret" in data or "msg" in data):
        return True, f"panel api ok (status={resp.status_code}, ret={data.get('ret')}, phase={data.get('phase')})"

    snippet = resp.text[:120].replace("\n", " ")
    return False, f"status={resp.status_code}, not json api, body={snippet}"


def resolve_base_url(configured: str) -> str:
    configured_n = normalize_base_url(configured or DEFAULT_URL)
    conf_host = host_from_url(configured_n)

    candidates: List[str] = []
    if conf_host in DIRECTORY_HOSTS:
        print(
            f"[url] configured host `{conf_host}` is a domain directory page, "
            f"not SSPanel. Will auto-select a panel host."
        )
    else:
        candidates.append(configured_n)

    # Dynamically discover the latest available panel domains from the
    # ikuuu.de directory page. Discovered hosts take priority over the static
    # PANEL_CANDIDATES list so the script keeps working when the panel migrates
    # to a brand-new domain.
    discovered = discover_panel_hosts()
    for item in discovered:
        item_n = normalize_base_url(item)
        if item_n not in candidates:
            candidates.append(item_n)

    for item in PANEL_CANDIDATES:
        item_n = normalize_base_url(item)
        if item_n not in candidates:
            candidates.append(item_n)

    # Always keep configured as last-resort even if directory host,
    # so probe logs remain clear.
    if configured_n not in candidates:
        candidates.append(configured_n)

    for cand in candidates:
        ok, info = probe_panel_api(cand)
        print(f"[url] probe {cand} -> {'OK' if ok else 'NO'} | {info}")
        if ok:
            if cand != configured_n:
                print(f"[url] switched {configured_n} -> {cand}")
            return cand

    print(
        "[url] WARNING: no healthy panel API found. "
        "Keep configured URL, login will likely fail with 405/HTML."
    )
    return configured_n if conf_host not in DIRECTORY_HOSTS else normalize_base_url(DEFAULT_URL)


@dataclass
class AccountResult:
    index: int
    account: str
    ok: bool
    stage: str
    message: str
    verification: str = "not checked"
    reward: str = ""

    def as_text(self) -> str:
        status = "SUCCESS" if self.ok else "FAIL"
        reward_line = f"\nreward: {self.reward}" if self.reward else ""
        return (
            f"[{status}] account#{self.index} {mask_account(self.account)}\n"
            f"stage: {self.stage}\n"
            f"verification: {self.verification}\n"
            f"message: {self.message}{reward_line}"
        )


@dataclass
class DashboardState:
    status: str
    authenticated: bool
    message: str


@dataclass
class DeliveryResult:
    channel: str
    configured: bool
    ok: bool
    message: str


class _DashboardParser(HTMLParser):
    """Collect check-in controls and the optional last-check-in timestamp."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.controls: List[dict] = []
        self.last_checkin_text = ""
        self._current: Optional[dict] = None
        self._depth = 0
        self._last_checkin_depth = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attrs_dict = {key.lower(): (value or "") for key, value in attrs}
        if self._current is not None:
            self._depth += 1
        elif tag.lower() in {"a", "button", "input"}:
            self._current = {"tag": tag.lower(), "attrs": attrs_dict, "text": []}
            self._depth = 1

        if attrs_dict.get("id", "").lower() == "last-checkin-time":
            self._last_checkin_depth = 1
        elif self._last_checkin_depth:
            self._last_checkin_depth += 1

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if self._current is not None:
            self._current["text"].append(data)
        if self._last_checkin_depth:
            self.last_checkin_text += data

    def handle_endtag(self, tag: str) -> None:
        if self._current is not None:
            self._depth -= 1
            if self._depth == 0:
                attrs = self._current["attrs"]
                if self._current["tag"] == "input" and attrs.get("value"):
                    self._current["text"].append(attrs["value"])
                self.controls.append(self._current)
                self._current = None
        if self._last_checkin_depth:
            self._last_checkin_depth -= 1


def checkin_timezone() -> ZoneInfo:
    try:
        return ZoneInfo(CHECKIN_TIMEZONE)
    except ZoneInfoNotFoundError:
        print(f"[verify] unknown timezone {CHECKIN_TIMEZONE!r}; fallback to UTC")
        return ZoneInfo("UTC")


def local_today() -> str:
    return datetime.now(checkin_timezone()).strftime("%Y-%m-%d")


def parse_dashboard_state(html: str) -> DashboardState:
    html = unwrap_origin_body(html)
    parser = _DashboardParser()
    try:
        parser.feed(html or "")
    except Exception as exc:
        return DashboardState("unknown", True, f"dashboard HTML parse failed: {exc}")

    for control in parser.controls:
        attrs = control["attrs"]
        text = re.sub(r"\s+", "", "".join(control["text"]))
        classes = attrs.get("class", "").lower().split()
        disabled = (
            "disabled" in attrs
            or "disabled" in classes
            or attrs.get("aria-disabled", "").lower() == "true"
        )
        signed_text = text.lower()
        signed_markers = (
            "已签到",
            "今日已领取",
            "已领取",
            "明日再来",
            "明天再来",
            "comebacktomorrow",
        )
        if disabled and any(marker in signed_text for marker in signed_markers):
            return DashboardState("signed", True, f"主页禁用的签到控件显示“{text}”")

    last_checkin = re.sub(r"\s+", " ", parser.last_checkin_text).strip()
    if last_checkin and local_today() in last_checkin:
        return DashboardState("signed", True, f"主页上次签到时间为 {last_checkin}")

    for control in parser.controls:
        attrs = control["attrs"]
        text = re.sub(r"\s+", "", "".join(control["text"]))
        marker = " ".join(
            [
                attrs.get("id", ""),
                attrs.get("class", ""),
                attrs.get("onclick", ""),
                attrs.get("hx-post", ""),
            ]
        ).lower()
        disabled = "disabled" in attrs or "disabled" in attrs.get("class", "").lower().split()
        exact_action = text.lower() in {"签到", "每日签到", "立即签到", "dailybonus"}
        if exact_action and not disabled and ("checkin" in marker or "check-in" in marker or control["tag"] == "button"):
            return DashboardState("unsigned", True, f"主页仍显示可用的“{text}”控件")

    return DashboardState("unknown", True, "主页未暴露可识别的签到状态")


def unwrap_origin_body(html: str) -> str:
    """Decode the Base64 HTML wrapper currently used by ikuuu pages."""
    if not html or "originBody" not in html:
        return html or ""
    match = re.search(
        r"(?:var\s+)?originBody\s*=\s*[\"']([A-Za-z0-9+/=\r\n]+)[\"']",
        html,
        re.I,
    )
    if not match:
        return html
    encoded = re.sub(r"\s+", "", match.group(1))
    if len(encoded) > 8_000_000:
        print("[verify] originBody is unexpectedly large; refusing to decode")
        return html
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except Exception as exc:
        print(f"[verify] originBody decode failed: {exc}")
        return html
    return decoded if "<" in decoded and ">" in decoded else html


def inspect_dashboard(session: requests.Session) -> DashboardState:
    try:
        response = session.get(
            f"{BASE_URL}/user",
            params={"checkin_verify": str(int(time.time() * 1000))},
            headers={"cache-control": "no-cache", "pragma": "no-cache"},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
    except Exception as exc:
        return DashboardState("unknown", False, f"读取主页失败: {exc}")

    final_path = urlparse(response.url).path.lower()
    if response.status_code >= 400:
        return DashboardState("unknown", False, f"读取主页 HTTP {response.status_code}")
    dashboard_html = unwrap_origin_body(response.text)
    if "/auth/login" in final_path or re.search(
        r"<form[^>]+(?:/auth/login|id=[\"']login)", dashboard_html[:20000], re.I
    ):
        return DashboardState("unknown", False, "主页跳回登录页，会话无效")
    return parse_dashboard_state(dashboard_html)


def _compact_message(value: str, limit: int = 180) -> str:
    value = re.sub(r"\s+", " ", value or "").strip()
    return value if len(value) <= limit else value[: limit - 1] + "…"


def extract_traffic_reward(message: str) -> str:
    """Extract a human-readable traffic reward from a successful API message."""
    match = re.search(r"(?<![\w.])(\d+(?:\.\d+)?)\s*(TB|GB|MB|KB|B)\b", message or "", re.I)
    if not match:
        return ""
    return f"{match.group(1)} {match.group(2).upper()}"


def build_notification(results: List[AccountResult]) -> Tuple[str, str, str, str]:
    total = len(results)
    success_count = sum(1 for result in results if result.ok)
    if success_count == total:
        overall = "签到成功"
    elif success_count:
        overall = "部分失败"
    else:
        overall = "签到失败"

    host = host_from_url(BASE_URL)
    timestamp = datetime.now(checkin_timezone()).strftime("%Y-%m-%d %H:%M:%S %Z")
    title = f"[{overall}] {success_count}/{total} · {host}"

    plain_lines = [
        "机场签到日报",
        f"结果：{overall}（{success_count}/{total}）",
        f"面板：{host}",
        f"时间：{timestamp}",
        "",
        "账号明细",
    ]
    markdown_lines = [
        f"## {overall}  {success_count}/{total}",
        "",
        f"- **面板：** `{host}`",
        f"- **时间：** {timestamp}",
    ]
    html_items: List[str] = []

    for result in results:
        status_text = "成功" if result.ok else "失败"
        status_color = "#087a55" if result.ok else "#b42318"
        account = mask_account(result.account)
        message = _compact_message(result.message)
        verification = _compact_message(result.verification, 120)
        reward = _compact_message(result.reward, 60)
        plain_lines.extend(
            [
                "",
                f"#{result.index} {account}  {status_text}",
                f"阶段：{result.stage}",
                f"验证：{verification}",
                *([f"本次奖励：{reward}"] if reward else []),
                f"说明：{message}",
            ]
        )
        markdown_lines.extend(
            [
                "",
                f"### #{result.index} `{account}`",
                f"- **结果：** {status_text}",
                f"- **阶段：** {result.stage}",
                f"- **主页验证：** {verification}",
                *([f"- **本次奖励：** `{reward}`"] if reward else []),
                f"- **说明：** {message}",
            ]
        )
        reward_row = (
            f'<tr><td style="width:78px;padding:8px 12px;color:#667085;vertical-align:top">本次奖励</td>'
            f'<td style="padding:8px 12px;font-weight:700;color:#087a55;word-break:break-word">{escape(reward)}</td></tr>'
            if reward
            else ""
        )
        html_items.append(
            '<div style="margin-bottom:12px;border:1px solid #e4e7ec;border-radius:8px;overflow:hidden">'
            '<div style="padding:11px 14px;background:#f9fafb;border-bottom:1px solid #e4e7ec">'
            f'<span style="font-weight:700">#{result.index} {escape(account)}</span>'
            f'<span style="float:right;font-weight:700;color:{status_color}">{status_text}</span>'
            "</div>"
            '<table role="presentation" style="width:100%;table-layout:fixed;border-collapse:collapse;font-size:14px;line-height:1.55">'
            f'<tr><td style="width:78px;padding:8px 12px;color:#667085;vertical-align:top">阶段</td><td style="padding:8px 12px;word-break:break-word">{escape(result.stage)}</td></tr>'
            f'<tr><td style="width:78px;padding:8px 12px;color:#667085;vertical-align:top">主页验证</td><td style="padding:8px 12px;word-break:break-word">{escape(verification)}</td></tr>'
            f'{reward_row}'
            f'<tr><td style="width:78px;padding:8px 12px;color:#667085;vertical-align:top">说明</td><td style="padding:8px 12px;word-break:break-word">{escape(message)}</td></tr>'
            "</table></div>"
        )

    summary_color = "#087a55" if success_count == total else "#b54708" if success_count else "#b42318"
    html_content = f"""<!doctype html>
<html lang="zh-CN">
<body style="margin:0;background:#f5f7fa;color:#182230;font-family:Arial,'Microsoft YaHei',sans-serif">
  <div style="max-width:760px;margin:0 auto;padding:24px 12px">
    <div style="background:#ffffff;border:1px solid #e4e7ec;border-radius:8px;overflow:hidden">
      <div style="padding:22px 24px;border-bottom:1px solid #e4e7ec">
        <div style="font-size:13px;color:#667085">机场签到日报</div>
        <div style="margin-top:6px;font-size:24px;font-weight:700;color:{summary_color}">{overall} {success_count}/{total}</div>
        <div style="margin-top:10px;font-size:13px;color:#667085">{escape(host)} · {escape(timestamp)}</div>
      </div>
      <div style="padding:18px 24px">
        {''.join(html_items)}
      </div>
    </div>
  </div>
</body>
</html>"""
    return title, "\n".join(plain_lines), "\n".join(markdown_lines), html_content


def send_serverchan(title: str, content: str) -> DeliveryResult:
    if not SCKEY:
        return DeliveryResult("Server酱", False, False, "未配置 SCKEY")
    api = f"https://sctapi.ftqq.com/{SCKEY}.send"
    try:
        resp = requests.post(api, data={"title": title, "desp": content}, timeout=REQUEST_TIMEOUT)
        data = parse_json_loose(resp.text) or {}
        code = data.get("code")
        if resp.ok and code in (0, "0"):
            return DeliveryResult("Server酱", True, True, f"投递成功 HTTP {resp.status_code}")
        detail = _compact_message(str(data.get("message") or resp.text), 160)
        return DeliveryResult("Server酱", True, False, f"HTTP {resp.status_code}, code={code}: {detail}")
    except Exception as exc:
        return DeliveryResult("Server酱", True, False, f"请求异常: {exc}")


def _email_recipients() -> List[str]:
    return [addr.strip() for addr in (MAIL_TO or "").split(",") if addr.strip()]


def send_email_resend(title: str, content: str, html_content: str) -> DeliveryResult:
    """Send mail over HTTPS. Works on GitHub Actions where SMTP ports are blocked."""
    if not RESEND_API_KEY:
        return DeliveryResult("邮件/Resend", False, False, "未配置 RESEND_API_KEY")
    recipients = _email_recipients()
    if not recipients:
        return DeliveryResult("邮件/Resend", True, False, "未配置 MAIL_TO")

    # SMTP identities are not automatically verified by Resend. Reusing a QQ
    # or other SMTP address here causes Resend to reject an otherwise valid request.
    sender = RESEND_FROM or "onboarding@resend.dev"
    payload = {
        "from": sender,
        "to": recipients,
        "subject": title,
        "text": content,
        "html": html_content,
    }
    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code < 300:
            data = parse_json_loose(resp.text) or {}
            message_id = data.get("id", "unknown")
            return DeliveryResult("邮件/Resend", True, True, f"投递成功 HTTP {resp.status_code}, id={message_id}")
        detail = _compact_message(resp.text, 220)
        if resp.status_code == 403 and "only send testing emails to your own email address" in detail.lower():
            allowed = re.search(r"\(([^()\s]+@[^()\s]+)\)", detail)
            allowed_text = allowed.group(1) if allowed else "Resend 账号邮箱"
            detail = (
                f"Resend 测试发件人只能发送到 {allowed_text}；如需发送到其他 MAIL_TO，"
                "请在 resend.com/domains 验证域名并设置 RESEND_FROM"
            )
        return DeliveryResult("邮件/Resend", True, False, f"HTTP {resp.status_code}: {detail}")
    except Exception as exc:
        return DeliveryResult("邮件/Resend", True, False, f"请求异常: {exc}")


def _smtp_error_message(exc: Exception) -> str:
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "SMTP 认证失败，请检查邮箱账号和授权码"
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "收件人被 SMTP 服务拒绝，请检查 MAIL_TO"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "连接超时；GitHub 托管 Runner 可能无法访问该 SMTP 端口"
    if isinstance(exc, ssl.SSLError):
        return f"TLS/SSL 握手失败: {exc}"
    if isinstance(exc, (ConnectionError, OSError)):
        return f"网络连接失败: {exc}"
    return f"{type(exc).__name__}: {exc}"


def send_email_smtp(title: str, content: str, html_content: str) -> DeliveryResult:
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and MAIL_TO):
        return DeliveryResult(
            "邮件/SMTP",
            False,
            False,
            "SMTP 配置不完整；可使用 SMTP_HOST/PORT/USER/PASS/TO，或 SMTP_SERVER/SMTP_ACCOUNT/MAIL_TO",
        )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = title
    msg["From"] = MAIL_FROM or SMTP_USER
    msg["To"] = MAIL_TO
    msg.attach(MIMEText(content, "plain", "utf-8"))
    msg.attach(MIMEText(html_content, "html", "utf-8"))
    recipients = _email_recipients()
    if not recipients:
        return DeliveryResult("邮件/SMTP", True, False, "MAIL_TO 中没有有效收件人")

    # Preferred mode first, then common fallbacks.
    attempts: List[Tuple[bool, int]] = []
    attempts.append((SMTP_SSL, SMTP_PORT))
    if SMTP_SSL:
        attempts.append((False, 587 if SMTP_PORT == 465 else SMTP_PORT))
        if SMTP_PORT != 465:
            attempts.append((True, 465))
    else:
        attempts.append((True, 465 if SMTP_PORT == 587 else SMTP_PORT))
        if SMTP_PORT != 587:
            attempts.append((False, 587))

    seen = set()
    errors: List[str] = []
    context = ssl.create_default_context()
    for use_ssl, port in attempts:
        key = (use_ssl, port)
        if key in seen:
            continue
        seen.add(key)
        mode = "SSL" if use_ssl else "STARTTLS"
        # Log host/port separately so GitHub secret masking does not turn
        # "smtp.qq.com:465" into a confusing "***".
        print(f"[push] SMTP try host={SMTP_HOST} port={port} mode={mode}")
        try:
            if use_ssl:
                with smtplib.SMTP_SSL(SMTP_HOST, port, timeout=REQUEST_TIMEOUT, context=context) as server:
                    server.login(SMTP_USER, SMTP_PASS)
                    server.sendmail(MAIL_FROM or SMTP_USER, recipients, msg.as_string())
            else:
                with smtplib.SMTP(SMTP_HOST, port, timeout=REQUEST_TIMEOUT) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    server.login(SMTP_USER, SMTP_PASS)
                    server.sendmail(MAIL_FROM or SMTP_USER, recipients, msg.as_string())
            return DeliveryResult("邮件/SMTP", True, True, f"投递成功 {SMTP_HOST}:{port} {mode}")
        except Exception as exc:
            err = f"{SMTP_HOST}:{port} {mode}: {_smtp_error_message(exc)}"
            print(f"[push] Email attempt failed: {err}")
            errors.append(err)
            if isinstance(exc, (smtplib.SMTPAuthenticationError, smtplib.SMTPRecipientsRefused)):
                break

    return DeliveryResult("邮件/SMTP", True, False, "；".join(errors))


def send_email(title: str, content: str, html_content: str) -> DeliveryResult:
    """Email notify with GitHub Actions-aware strategy.

    Notes:
    - Your SMTP_SERVER value like smtp.qq.com:465 is fine.
    - GitHub-hosted runners commonly block outbound SMTP 25/465/587, which
      surfaces as "Connection unexpectedly closed" before AUTH.
    - On Actions, prefer Resend HTTPS if RESEND_API_KEY is configured.
    """
    on_gha = os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
    has_smtp = bool(SMTP_HOST and SMTP_USER and SMTP_PASS and MAIL_TO)
    has_resend = bool(RESEND_API_KEY and MAIL_TO)
    smtp_requested = bool(
        SMTP_SERVER
        or SMTP_ACCOUNT
        or SMTP_HOST_ENV
        or SMTP_PORT_ENV
        or SMTP_USER_ENV
        or SMTP_PASS_ENV
        or SMTP_TO_ENV
        or SMTP_FROM_ENV
    )
    resend_requested = bool(RESEND_API_KEY or RESEND_FROM)

    if not has_smtp and not has_resend:
        errors: List[str] = []
        if resend_requested:
            errors.append("Resend 缺少 RESEND_API_KEY 或 MAIL_TO")
        if smtp_requested:
            errors.append(
                "SMTP 配置不完整；请检查 SMTP_HOST/PORT/USER/PASS/TO，"
                "或 SMTP_SERVER/SMTP_ACCOUNT/MAIL_TO"
            )
        if errors:
            return DeliveryResult("邮件", True, False, "；".join(errors))
        return DeliveryResult("邮件", False, False, "未配置邮件渠道")

    if on_gha:
        if has_smtp and not has_resend:
            print(
                "[push] Running on GitHub Actions with SMTP configured but no RESEND_API_KEY. "
                "GitHub Actions blocks outbound SMTP ports 465/587. "
                "Configure RESEND_API_KEY secret to send email via HTTPS."
            )
        if has_smtp and has_resend:
            print(
                "[push] Running on GitHub Actions with SMTP configured: outbound ports "
                "465/587 may be unavailable. Will prefer Resend HTTPS when configured."
            )
        if has_resend:
            resend_result = send_email_resend(title, content, html_content)
            if resend_result.ok:
                return resend_result
        if has_smtp:
            smtp_result = send_email_smtp(title, content, html_content)
            if smtp_result.ok:
                return smtp_result
            if has_resend:
                smtp_result.message = f"Resend: {resend_result.message}；SMTP: {smtp_result.message}"
            return smtp_result
        return resend_result

    # Local / self-hosted: SMTP first, Resend fallback.
    if has_smtp:
        smtp_result = send_email_smtp(title, content, html_content)
        if smtp_result.ok:
            return smtp_result
    if has_resend:
        resend_result = send_email_resend(title, content, html_content)
        if resend_result.ok:
            return resend_result
        if has_smtp:
            resend_result.message = f"SMTP: {smtp_result.message}；Resend: {resend_result.message}"
        return resend_result
    return smtp_result


def notify(title: str, plain_content: str, markdown_content: str, html_content: str) -> List[DeliveryResult]:
    print("--- notify ---")
    print(title)
    print(plain_content)
    print("--------------")
    results = [
        send_serverchan(title, markdown_content),
        send_email(title, plain_content, html_content),
    ]
    print("--- delivery report ---")
    for result in results:
        state = "SUCCESS" if result.ok else "SKIP" if not result.configured else "FAIL"
        print(f"[push] {result.channel}: {state} | {result.message}")
    print("-----------------------")
    return results


class _LotParser:
    def __init__(self, mapping: Optional[Dict[str, str]] = None):
        self.mapping = mapping or {"n[3:5]+n[9:11]": "n[7:12]"}
        self.lot: List = []
        self.lot_res: List = []
        for k, v in self.mapping.items():
            self.lot = self._parse(k)
            self.lot_res = self._parse(v)

    @staticmethod
    def _parse_slice(s: str):
        return [int(x) for x in s.split(":")]

    @staticmethod
    def _extract(part: str):
        res = re.search(r"\[(.*?)\]", part)
        return res.group(1) if res else ""

    def _parse(self, s: str):
        parts = s.split("+.+")
        parsed = []
        for part in parts:
            if "+" in part:
                subs = part.split("+")
                parsed_subs = [self._parse_slice(self._extract(sub)) for sub in subs]
                parsed.append(parsed_subs)
            else:
                extracted = self._extract(part)
                if extracted:
                    parsed.append([self._parse_slice(extracted)])
        return parsed

    @staticmethod
    def _build_str(parsed, num: str):
        result = []
        for p in parsed:
            current = []
            for s in p:
                start = s[0]
                end = s[1] + 1 if len(s) > 1 else start + 1
                current.append(num[start:end])
            result.append("".join(current))
        return ".".join(result)

    def get_dict(self, lot_number: str) -> dict:
        i = self._build_str(self.lot, lot_number)
        r = self._build_str(self.lot_res, lot_number)
        parts = i.split(".")
        a: dict = {}
        current = a
        for idx, part in enumerate(parts):
            if idx == len(parts) - 1:
                current[part] = r
            else:
                current[part] = current.get(part, {})
                current = current[part]
        return a


class _GeeSigner:
    encryptor_pubkey = construct(
        (
            int(
                "00C1E3934D1614465B33053E7F48EE4EC87B14B95EF88947713D25EECBFF7E74C7977D02DC1D9451F79DD5D1C10C29ACB6A9B4D6FB7D0A0279B6719E1772565F09AF627715919221AEF91899CAE08C0D686D748B20A3603BE2318CA6BC2B59706592A9219D0BF05C9F65023A21D2330807252AE0066D59CEEFA5F2748EA80BAB81".lower(),
                16,
            ),
            int("10001", 16),
        )
    )

    @staticmethod
    def rand_uid() -> str:
        result = ""
        for _ in range(4):
            result += hex(int(65536 * (1 + random.random())))[2:].zfill(4)[-4:]
        return result

    @staticmethod
    def encrypt_symmetrical_1(o_text: str, random_str: str) -> bytes:
        key = random_str.encode("utf-8")
        iv = b"0000000000000000"
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(o_text.encode("utf-8"), AES.block_size))

    @staticmethod
    def encrypt_asymmetric_1(message: str) -> str:
        message_bytes = message.encode("utf-8")
        cipher = PKCS1_v1_5.new(_GeeSigner.encryptor_pubkey)
        encrypted_bytes = cipher.encrypt(message_bytes)
        return binascii.hexlify(encrypted_bytes).decode("utf-8")

    @staticmethod
    def encrypt_w(raw_input: str, pt: str) -> str:
        if not pt or "0" == pt:
            return quote_plus(raw_input)
        random_uid = _GeeSigner.rand_uid()
        if pt == "1":
            enc_key = _GeeSigner.encrypt_asymmetric_1(random_uid)
            enc_input = _GeeSigner.encrypt_symmetrical_1(raw_input, random_uid)
            return binascii.hexlify(enc_input).decode() + enc_key
        raise NotImplementedError("Encryption pt != 1 not implemented")

    @staticmethod
    def generate_pow(
        lot_number_pow: str,
        captcha_id_pow: str,
        hash_func: str,
        hash_version: int,
        bits: int,
        date: str,
        empty: str,
    ) -> dict:
        bit_remainder = bits % 4
        bit_division = bits // 4
        prefix = "0" * bit_division
        pow_string = f"{hash_version}|{bits}|{hash_func}|{date}|{captcha_id_pow}|{lot_number_pow}|{empty}|"
        while True:
            h = _GeeSigner.rand_uid()
            combined = pow_string + h
            if hash_func == "md5":
                hashed_value = hashlib.md5(combined.encode("utf-8")).hexdigest()
            elif hash_func == "sha1":
                hashed_value = hashlib.sha1(combined.encode("utf-8")).hexdigest()
            elif hash_func == "sha256":
                hashed_value = hashlib.sha256(combined.encode("utf-8")).hexdigest()
            else:
                raise ValueError(f"Unsupported hash function: {hash_func}")
            if hashed_value.startswith(prefix):
                if bit_remainder == 0:
                    return {"pow_msg": pow_string + h, "pow_sign": hashed_value}
                threshold = {1: 7, 2: 3, 3: 1}.get(bit_remainder)
                if threshold is not None and len(prefix) <= threshold:
                    return {"pow_msg": pow_string + h, "pow_sign": hashed_value}

    @staticmethod
    def generate_w(
        data: dict, captcha_id: str, risk_type: str, constants: Optional[dict] = None,
        icon_positions: Optional[list] = None,
    ) -> str:
        constants = constants or {
            "abo": {"1a8R": "daC2"},
            "mapping": {"n[3:5]+n[9:11]": "n[7:12]"},
        }
        lot_number = data["lot_number"]
        pow_detail = data["pow_detail"]
        parser = _LotParser(constants["mapping"])
        base = {
            **constants["abo"],
            **_GeeSigner.generate_pow(
                lot_number,
                captcha_id,
                pow_detail["hashfunc"],
                pow_detail["version"],
                pow_detail["bits"],
                pow_detail["datetime"],
                "",
            ),
            **parser.get_dict(lot_number),
            "biht": "1426265548",
            "device_id": "",
            "em": {"cp": 0, "ek": "11", "nt": 0, "ph": 0, "sc": 0, "si": 0, "wd": 1},
            "gee_guard": {
                "roe": {
                    "auh": "3", "aup": "3", "cdc": "3", "egp": "3",
                    "res": "3", "rew": "3", "sep": "3", "snh": "3",
                }
            },
            "ep": "123",
            "geetest": "captcha",
            "lang": "zh",
            "lot_number": lot_number,
        }
        if risk_type in ("ai", "invisible"):
            pass
        elif risk_type in ("icon", "word") and icon_positions is not None:
            base["passtime"] = random.randint(600, 1200)
            base["userresponse"] = icon_positions
        return _GeeSigner.encrypt_w(json.dumps(base), data["pt"])


_GEETEST_CONSTANTS_CANDIDATES = [
    {
        "label": "legacy",
        "abo": {"1a8R": "daC2"},
        "mapping": {"n[3:5]+n[9:11]": "n[7:12]"},
    },
    {
        "label": "alt",
        "abo": {"4MTT": "0Qh0"},
        "mapping": {"(n[19:24])+.+(n[23:30])+.+(n[5:12])": "n[14:19]"},
    },
]


def _geetest_callback() -> str:
    return f"geetest_{int(random.random() * 10000) + int(time.time() * 1000)}"


def _parse_jsonp(raw: str, callback: str) -> dict:
    prefix = f"{callback}("
    text = raw.strip()
    if not text.startswith(prefix):
        raise ValueError(f"Unexpected JSONP response: {text[:120]}")
    if text.endswith(");"):
        payload = text[len(prefix):-2]
    elif text.endswith(")"):
        payload = text[len(prefix):-1]
    else:
        payload = text[len(prefix):]
    return json.loads(payload)


def _extract_seccode(verify_data: dict) -> Optional[dict]:
    seccode = verify_data.get("seccode")
    if isinstance(seccode, dict):
        return seccode
    if all(k in verify_data for k in ("lot_number", "captcha_output", "pass_token", "gen_time")):
        return {
            "lot_number": str(verify_data["lot_number"]),
            "captcha_output": str(verify_data["captcha_output"]),
            "pass_token": str(verify_data["pass_token"]),
            "gen_time": str(verify_data["gen_time"]),
        }
    return None


_ICON_MAPPING = {
    "8da090c135ff029f3b5e19f4c44f73c8.png": "u",
    "cb0eaa639b2117a69a81af3d8c1496a1.png": "d",
    "315ce8665e781dabcd1eb09d3e604803.png": "l",
    "38bd9dda695098c7dfad74c921923a7d.png": "lu",
    "502e51dbabf411beba2dcd55fd38ebbd.png": "ld",
    "2b2387f566f6a03ed594d4d7cfda471f.png": "r",
    "78dc29045d587ad054c7353732df53c5.png": "ru",
    "23ef93e6b0e0df0e15b66667c99a5fb4.png": "rd",
}

_ICON_MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "geetest_v4_icon.onnx")
_ICON_CHARSETS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "charsets.json")
_ICON_STATIC_URL = "https://static.geevisit.com"
_dddd_det = None
_dddd_cnn = None
_dddd_ocr = None


def _ensure_dddd():
    global _dddd_det, _dddd_cnn, _dddd_ocr
    if _dddd_det is not None and _dddd_ocr is not None:
        return
    import ddddocr
    _dddd_det = ddddocr.DdddOcr(det=True, show_ad=False)
    _dddd_ocr = ddddocr.DdddOcr(show_ad=False)
    if os.path.exists(_ICON_MODEL_PATH) and os.path.exists(_ICON_CHARSETS_PATH):
        _dddd_cnn = ddddocr.DdddOcr(
            det=False, ocr=False, show_ad=False,
            import_onnx_path=_ICON_MODEL_PATH,
            charsets_path=_ICON_CHARSETS_PATH,
        )
    else:
        _dddd_cnn = _dddd_ocr


class IconSolver:
    """Solve GeeTest V4 icon/word captcha by matching question icons to grid positions.

    Uses ddddocr detection to locate grid cells in the big image, then OCR to
    classify each cell. Question icons are also OCR'd and matched against the
    grid. Falls back to slide_match (template matching) when OCR returns empty.
    """

    def __init__(self, imgs_path: str, ques: list, http_get=None):
        self.imgs_url = f"{_ICON_STATIC_URL}/{imgs_path}"
        self.ques = ques
        self._get = http_get or _default_icon_http_get
        self.imgs_bytes = self._get(self.imgs_url)

    def find_icon_position(self):
        _ensure_dddd()
        import cv2
        import numpy as np

        bboxes = _dddd_det.detection(self.imgs_bytes)
        im = cv2.imdecode(np.frombuffer(self.imgs_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)

        # OCR each grid cell
        grid_texts = []
        grid_centers = []
        for bbox in bboxes:
            x1, y1, x2, y2 = bbox
            cell = im[y1:y2, x1:x2]
            _, cell_bytes = cv2.imencode(".png", cell)
            text = _dddd_ocr.classification(cell_bytes.tobytes())
            grid_texts.append(text)
            grid_centers.append([(x1 + (x2 - x1) / 2) * 33, (y1 + (y2 - y1) / 2) * 49])

        # OCR each ques icon (composite on white to handle transparency)
        ques_texts = []
        for q in self.ques:
            q_url = f"{_ICON_STATIC_URL}/{q}"
            q_bytes = self._get(q_url)
            q_img = cv2.imdecode(np.frombuffer(q_bytes, dtype=np.uint8), cv2.IMREAD_UNCHANGED)
            text = _dddd_ocr.classification(q_bytes)
            if not text and q_img is not None and q_img.ndim == 3 and q_img.shape[2] == 4:
                alpha = q_img[:, :, 3]
                bgr = q_img[:, :, :3]
                white_bg = np.ones_like(bgr) * 255
                composited = np.where(alpha[:, :, np.newaxis] > 128, bgr, white_bg)
                _, comp_bytes = cv2.imencode(".png", composited)
                text = _dddd_ocr.classification(comp_bytes.tobytes())
            ques_texts.append(text)

        # Match ques to grid by text
        results = []
        used = set()
        for qt in ques_texts:
            matched = False
            for i, gt in enumerate(grid_texts):
                if gt and qt and gt == qt and i not in used:
                    results.append(grid_centers[i])
                    used.add(i)
                    matched = True
                    break
            if not matched and grid_centers:
                # Fallback: pick an unused cell randomly
                available = [j for j in range(len(grid_centers)) if j not in used]
                if available:
                    pick = random.choice(available)
                    results.append(grid_centers[pick])
                    used.add(pick)

        return results


def _default_icon_http_get(url):
    resp = requests.get(url, timeout=15)
    resp.raise_for_status()
    return resp.content


class GeetestSolver:
    """Standalone GeeTest V4 solver with multi-round ``continue`` support.

    Unlike the upstream ``geeked`` library, this implementation:
      - uses the correct ``abo``/``mapping`` obfuscation constants for ikuuu
        (the upstream constants are wrong and cause GeeTest to reject ``w``)
      - loops the load→verify cycle when ``result == "continue"`` is returned,
        resubmitting with the new payload/process_token until ``result ==
        "success"`` yields a ``seccode``
    """

    BASE_URL = "https://gcaptcha4.geevisit.com"

    def __init__(self, captcha_id: str, risk_type: str = "ai"):
        self.captcha_id = captcha_id
        self.risk_type = risk_type
        self.session = requests.Session()
        self.session.headers.update({
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        })

    def _get(self, url: str, params: dict, timeout: int = 15):
        return self.session.get(url, params=params, timeout=timeout)

    def solve(self, max_attempts: int = 30, max_duration_seconds: int = 180) -> dict:
        continuation_context: Optional[dict] = None
        current_challenge = str(uuid4())
        started_at = time.time()
        continue_streak = 0

        for round_idx in range(max_attempts):
            if time.time() - started_at >= max_duration_seconds:
                break

            in_continuation = (
                continuation_context is not None
                and continuation_context.get("continuation_mode") is True
            )
            if not in_continuation:
                current_challenge = str(uuid4())

            callback = _geetest_callback()
            params = {
                "captcha_id": self.captcha_id,
                "challenge": continuation_context["challenge"] if in_continuation else current_challenge,
                "client_type": "web",
                "risk_type": self.risk_type,
                "lang": "zh",
                "callback": callback,
            }
            if in_continuation:
                params["lot_number"] = continuation_context["lot_number"]
                params["payload"] = continuation_context["payload"]
                params["process_token"] = continuation_context["process_token"]
                params["payload_protocol"] = continuation_context.get("payload_protocol", "1")
                params["pt"] = continuation_context.get("pt", "1")

            res = self._get(f"{self.BASE_URL}/load", params=params)
            try:
                load_parsed = _parse_jsonp(res.text, callback)
            except Exception:
                time.sleep(0.5 + random.random() * 0.25)
                continue

            if not isinstance(load_parsed, dict):
                time.sleep(0.5 + random.random() * 0.25)
                continue
            data = load_parsed.get("data") or {}
            if not data.get("lot_number") or not data.get("pow_detail") or not data.get("payload") or not data.get("process_token"):
                time.sleep(0.5 + random.random() * 0.25)
                continue

            captcha_type = str(data.get("captcha_type") or self.risk_type).lower()
            icon_positions = None
            effective_risk = self.risk_type
            if captcha_type in ("icon", "word") and data.get("imgs") and data.get("ques"):
                try:
                    solver_icon = IconSolver(
                        data["imgs"], data["ques"], http_get=lambda u: self.session.get(u, timeout=15).content
                    )
                    icon_positions = solver_icon.find_icon_position()
                    effective_risk = captcha_type
                    print(f"[captcha] {captcha_type} solved positions: {icon_positions}")
                except Exception as exc:
                    print(f"[captcha] icon solve failed: {exc}")
                    time.sleep(0.5 + random.random() * 0.25)
                    continue

            constants = _GEETEST_CONSTANTS_CANDIDATES[round_idx % len(_GEETEST_CONSTANTS_CANDIDATES)]
            try:
                w = _GeeSigner.generate_w(data, self.captcha_id, effective_risk, constants=constants, icon_positions=icon_positions)
            except Exception:
                time.sleep(0.5 + random.random() * 0.25)
                continue

            callback = _geetest_callback()
            verify_params = {
                "callback": callback,
                "captcha_id": self.captcha_id,
                "client_type": "web",
                "lot_number": data["lot_number"],
                "risk_type": effective_risk,
                "payload": data["payload"],
                "process_token": data["process_token"],
                "payload_protocol": "1",
                "pt": data.get("pt", "1"),
                "w": w,
            }
            res = self._get(f"{self.BASE_URL}/verify", params=verify_params)
            try:
                verify_parsed = _parse_jsonp(res.text, callback)
            except Exception:
                time.sleep(0.5 + random.random() * 0.25)
                continue

            if not isinstance(verify_parsed, dict):
                time.sleep(0.5 + random.random() * 0.25)
                continue
            verify_data = verify_parsed.get("data") or {}

            if verify_data.get("result") == "success":
                seccode = _extract_seccode(verify_data)
                if seccode:
                    return seccode
                raise RuntimeError(f"Geetest success without seccode: {verify_data}")

            result = str(verify_data.get("result", "")).lower()
            if result in ("continue", "continued"):
                continue_streak += 1
                # GeeTest may escalate to image captcha (nine/icon) after continue.
                # Resetting the challenge gives a fresh chance at a direct success
                # instead of getting stuck in image-captcha continuation loops.
                if continue_streak >= 6:
                    continuation_context = None
                    continue_streak = 0
                    current_challenge = str(uuid4())
                    time.sleep(0.8 + random.random() * 0.5)
                else:
                    continuation_context = {
                        "challenge": continuation_context["challenge"] if in_continuation else current_challenge,
                        "lot_number": str(verify_data.get("lot_number") or data.get("lot_number") or ""),
                        "payload": str(verify_data.get("payload") or data.get("payload") or ""),
                        "process_token": str(verify_data.get("process_token") or data.get("process_token") or ""),
                        "payload_protocol": str(verify_data.get("payload_protocol") or data.get("payload_protocol") or "1"),
                        "pt": str(verify_data.get("pt") or data.get("pt") or "1"),
                        "continuation_mode": True,
                    }
                    time.sleep(0.5 + random.random() * 0.3)
                continue

            # verify returned error or unknown result — reset challenge and retry
            continuation_context = None
            continue_streak = 0
            current_challenge = str(uuid4())
            time.sleep(0.5 + random.random() * 0.25)

        raise RuntimeError("captcha solve exhausted all attempts without success")


def solve_captcha() -> Optional[dict]:
    for attempt in range(1, MAX_CAPTCHA_RETRIES + 1):
        try:
            print(
                f"[captcha] solve attempt {attempt}/{MAX_CAPTCHA_RETRIES} "
                f"(id={CAPTCHA_ID}, risk={CAPTCHA_RISK_TYPE})"
            )
            solver = GeetestSolver(CAPTCHA_ID, CAPTCHA_RISK_TYPE)
            result = solver.solve(max_attempts=40, max_duration_seconds=150)
            if not result or not result.get("lot_number"):
                raise RuntimeError(f"empty captcha result: {result}")
            print("[captcha] solved")
            return result
        except Exception as exc:
            print(f"[captcha] failed: {exc}")
            if attempt < MAX_CAPTCHA_RETRIES:
                time.sleep(2 * attempt)
    return None


def build_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "user-agent": UA,
            "accept": "application/json, text/javascript, */*; q=0.01",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
        }
    )
    return session


def ajax_headers(referer: str) -> Dict[str, str]:
    return {
        "origin": BASE_URL,
        "referer": referer,
        "x-requested-with": "XMLHttpRequest",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "user-agent": UA,
    }


def login(session: requests.Session, email: str, password: str) -> Tuple[bool, str, dict]:
    global BASE_URL
    login_page = f"{BASE_URL}/auth/login"
    try:
        session.get(login_page, timeout=REQUEST_TIMEOUT)
    except Exception as exc:
        return False, f"open login page failed: {exc}", {}

    captcha = solve_captcha()
    if captcha is None:
        return (
            False,
            "captcha solve failed; site requires GeeTest V4. "
            "Without captcha, server returns verification rejected / reset_login.",
            {},
        )

    payload = {
        "host": host_from_url(BASE_URL),
        "email": email,
        "passwd": password,
        "code": "",
        "twofa_step": 0,
        "pageLoadedAt": str(int(time.time() * 1000)),
        "captcha_result[lot_number]": captcha.get("lot_number", ""),
        "captcha_result[captcha_output]": captcha.get("captcha_output", ""),
        "captcha_result[pass_token]": captcha.get("pass_token", ""),
        "captcha_result[gen_time]": captcha.get("gen_time", ""),
    }

    try:
        resp = session.post(
            f"{BASE_URL}/auth/login",
            headers=ajax_headers(login_page),
            data=payload,
            timeout=REQUEST_TIMEOUT,
        )
    except Exception as exc:
        return False, f"login request failed: {exc}", {}

    if resp.status_code == 405:
        # One more auto-switch attempt if panel host changed.
        alt = resolve_base_url(DEFAULT_URL)
        if alt != BASE_URL:
            print(f"[login] got 405 on {BASE_URL}, retry with {alt}")
            BASE_URL = alt
            return login(session, email, password)
        return (
            False,
            "login 405 Not Allowed. URL is not the SSPanel panel. "
            "Use https://ikuuu.win (panel), not https://ikuuu.co (domain bulletin).",
            {},
        )

    data = parse_json_loose(resp.text)
    if not data:
        snippet = resp.text[:200].replace("\n", " ")
        hint = ""
        if "405" in snippet or resp.status_code == 405:
            hint = " | Hint: URL may be domain bulletin page (ikuuu.co), set URL=https://ikuuu.win"
        return False, f"login response is not JSON (status={resp.status_code}): {snippet}{hint}", {}

    ret = data.get("ret")
    msg = str(data.get("msg") or "")
    # strip simple html from msg for cleaner push
    msg_plain = re.sub(r"<br\s*/?>", "\n", msg, flags=re.I)
    msg_plain = re.sub(r"<[^>]+>", "", msg_plain).strip()
    phase = str(data.get("phase") or "")

    if ret in (1, "1"):
        return True, msg_plain or "login ok", data
    if ret == 2:
        return False, f"account requires 2FA (phase={phase}): {msg_plain}", data
    if phase == "reset_login" or "verification" in msg_plain.lower() or any(
        k in msg_plain for k in ("\u9a8c\u8bc1", "\u6821\u9a8c", "\u4eba\u673a")
    ):
        return (
            False,
            f"captcha/login rejected (phase={phase}): {msg_plain}. "
            "Login did NOT succeed; any traffic gain today is not from this run.",
            data,
        )
    return False, f"login failed (ret={ret}, phase={phase}): {msg_plain}", data


def checkin(session: requests.Session) -> Tuple[bool, str, dict]:
    """POST /user/checkin with bounded retry.

    Retries on network errors or transient non-JSON responses (the ikuuu
    checkin endpoint occasionally rate-limits or returns HTML under load).
    Does NOT retry when the session is clearly unauthenticated (redirected
    to /auth/login) because retrying without re-login cannot succeed.
    Borrowed from the Tampermonkey checkin script's bounded-retry approach.
    """
    last_msg = ""
    last_data: dict = {}
    for attempt in range(1, MAX_CHECKIN_RETRIES + 1):
        try:
            resp = session.post(
                f"{BASE_URL}/user/checkin",
                headers=ajax_headers(f"{BASE_URL}/user"),
                timeout=REQUEST_TIMEOUT,
            )
        except Exception as exc:
            last_msg = f"checkin request failed (attempt {attempt}/{MAX_CHECKIN_RETRIES}): {exc}"
            print(f"[checkin] {last_msg}")
            if attempt < MAX_CHECKIN_RETRIES:
                time.sleep(1 + random.random() * 3)
            continue

        data = parse_json_loose(resp.text)
        if not data:
            if "auth/login" in resp.url or "login" in resp.text.lower()[:500]:
                return False, "checkin failed: not logged in (redirected to login page)", {}
            snippet = resp.text[:200].replace("\n", " ")
            last_msg = f"checkin response is not JSON (attempt {attempt}/{MAX_CHECKIN_RETRIES}): {snippet}"
            last_data = {}
            print(f"[checkin] {last_msg}")
            if attempt < MAX_CHECKIN_RETRIES:
                time.sleep(1 + random.random() * 3)
            continue

        msg = str(data.get("msg") or data)
        last_msg = re.sub(r"<[^>]+>", "", re.sub(r"<br\s*/?>", "\n", msg, flags=re.I)).strip()
        last_data = data
        ret = data.get("ret")
        if ret in (1, "1"):
            return True, last_msg, data
        # Non-success ret from the panel is a definitive answer; do not retry.
        return False, last_msg or f"unknown checkin response (ret={ret})", data

    return False, last_msg or "checkin exhausted all retries", last_data


def sign_one(index: int, email: str, password: str) -> AccountResult:
    print(f"\n=== account#{index} {mask_account(email)} ===")
    session = build_session()

    ok_login, login_msg, login_data = login(session, email, password)
    print(f"[login] ok={ok_login} msg={login_msg}")
    if login_data:
        print(f"[login] raw_ret={login_data.get('ret')} phase={login_data.get('phase')}")

    if not ok_login:
        return AccountResult(index, email, False, "登录", login_msg, "登录未成功，未执行签到")

    before = inspect_dashboard(session)
    print(
        f"[verify] before status={before.status} authenticated={before.authenticated} "
        f"msg={before.message}"
    )
    if not before.authenticated:
        return AccountResult(index, email, False, "主页验证", before.message, "登录态无效")
    if before.status == "signed":
        return AccountResult(index, email, True, "已签到", "执行前主页已经确认今日签到", before.message)

    ok_checkin, checkin_msg, checkin_data = checkin(session)
    reward = extract_traffic_reward(checkin_msg) if ok_checkin else ""
    print(f"[checkin] ok={ok_checkin} msg={checkin_msg}")
    if checkin_data:
        print(f"[checkin] raw={json.dumps(checkin_data, ensure_ascii=False)}")
    time.sleep(1)
    after = inspect_dashboard(session)
    print(
        f"[verify] after status={after.status} authenticated={after.authenticated} "
        f"msg={after.message}"
    )

    if after.status == "signed" and after.authenticated:
        api_note = "接口返回成功" if ok_checkin else "接口未报成功，但主页确认已签到"
        return AccountResult(
            index,
            email,
            True,
            "签到并验证",
            f"{api_note}：{checkin_msg}",
            after.message,
            reward,
        )
    if after.status == "unsigned":
        return AccountResult(
            index,
            email,
            False,
            "签到验证失败",
            f"接口返回：{checkin_msg}；但主页仍显示可签到，因此不判定成功",
            after.message,
            reward,
        )
    if ok_checkin and after.authenticated:
        return AccountResult(
            index,
            email,
            True,
            "签到成功（接口确认）",
            f"接口 ret=1：{checkin_msg}",
            f"{after.message}；接口已明确确认本次签到成功",
            reward,
        )
    return AccountResult(
        index,
        email,
        False,
        "签到待确认",
        f"接口返回：{checkin_msg}；主页状态无法确认，已按失败处理以避免误报",
        after.message,
    )


def parse_accounts(config_text: str) -> List[Tuple[str, str]]:
    lines = [ln.strip() for ln in config_text.splitlines() if ln.strip()]
    if not lines:
        raise ValueError("CONFIG is empty")
    if len(lines) % 2 != 0:
        raise ValueError("CONFIG format error: expect email/password on alternating lines")
    return [(lines[i], lines[i + 1]) for i in range(0, len(lines), 2)]


def main() -> int:
    global BASE_URL
    print(f"URL_RAW={URL_RAW}")
    BASE_URL = resolve_base_url(URL_RAW)
    print(f"BASE_URL={BASE_URL}")
    print(f"CAPTCHA_ID={CAPTCHA_ID}")
    print(f"CAPTCHA_RISK_TYPE={CAPTCHA_RISK_TYPE}")

    if not CONFIG:
        print("ERROR: env CONFIG is required (email/password alternating lines)")
        return 1

    try:
        accounts = parse_accounts(CONFIG)
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 1

    results: List[AccountResult] = []
    for idx, (email, password) in enumerate(accounts, start=1):
        try:
            results.append(sign_one(idx, email, password))
        except Exception as exc:
            results.append(AccountResult(idx, email, False, "程序异常", str(exc), "未完成主页验证"))
        time.sleep(1)

    success_count = sum(1 for r in results if r.ok)
    title, plain_summary, markdown_summary, html_summary = build_notification(results)
    deliveries = notify(title, plain_summary, markdown_summary, html_summary)

    all_accounts_ok = success_count == len(results)
    configured_deliveries = [delivery for delivery in deliveries if delivery.configured]
    notification_ok = any(delivery.ok for delivery in configured_deliveries)
    if REQUIRE_NOTIFICATION_SUCCESS and not notification_ok:
        print("ERROR: REQUIRE_NOTIFICATION_SUCCESS is enabled, but no notification channel succeeded")
        return 3
    return 0 if all_accounts_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
