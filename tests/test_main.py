import sys
import unittest
import base64
from pathlib import Path
from unittest.mock import Mock, patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main


class DashboardStateTests(unittest.TestCase):
    def test_disabled_signed_button_is_signed(self):
        state = main.parse_dashboard_state(
            '<a class="btn disabled" disabled="disabled">已签到</a>'
        )
        self.assertEqual(state.status, "signed")

    def test_modern_checkin_button_is_unsigned(self):
        state = main.parse_dashboard_state(
            '<button id="check-in" hx-post="/user/checkin">签到</button>'
        )
        self.assertEqual(state.status, "unsigned")

    def test_malio_daily_bonus_link_is_unsigned(self):
        state = main.parse_dashboard_state(
            '<div id="checkin-div"><a onclick="checkin()" class="btn">Daily Bonus</a></div>'
        )
        self.assertEqual(state.status, "unsigned")

    def test_malio_disabled_link_is_signed(self):
        state = main.parse_dashboard_state(
            '<div id="checkin-div"><a class="btn disabled">Come back tomorrow</a></div>'
        )
        self.assertEqual(state.status, "signed")

    def test_ikuuu_actual_tomorrow_link_is_signed(self):
        state = main.parse_dashboard_state(
            '<a class="btn btn-icon disabled icon-left btn-primary">明日再来</a>'
        )
        self.assertEqual(state.status, "signed")

    def test_legacy_checkin_link_is_unsigned(self):
        state = main.parse_dashboard_state(
            '<a id="checkin" onclick="index.checkin();">每日签到</a>'
        )
        self.assertEqual(state.status, "unsigned")

    def test_today_last_checkin_time_is_signed(self):
        today = main.local_today()
        state = main.parse_dashboard_state(
            f'<code id="last-checkin-time">{today} 08:30:00</code>'
        )
        self.assertEqual(state.status, "signed")

    def test_unrecognized_page_is_unknown(self):
        state = main.parse_dashboard_state("<html><body>用户中心</body></html>")
        self.assertEqual(state.status, "unknown")

    def test_ikuuu_base64_wrapper_is_decoded(self):
        inner = '<button id="checkin" onclick="index.checkin();">每日签到</button>'
        encoded = base64.b64encode(inner.encode("utf-8")).decode("ascii")
        wrapper = f'<script>var originBody = "{encoded}"; document.write(originBody);</script>'

        state = main.parse_dashboard_state(wrapper)

        self.assertEqual(state.status, "unsigned")

    def test_wrapped_login_page_is_not_authenticated_dashboard(self):
        inner = '<form id="login-form" action="/auth/login"></form>'
        encoded = base64.b64encode(inner.encode("utf-8")).decode("ascii")
        response = Mock(
            status_code=200,
            url="https://example.com/user",
            text=f'<script>var originBody = "{encoded}";</script>',
        )
        session = Mock()
        session.get.return_value = response

        state = main.inspect_dashboard(session)

        self.assertFalse(state.authenticated)


class CheckinDecisionTests(unittest.TestCase):
    def test_extracts_traffic_reward_from_success_popup(self):
        self.assertEqual(main.extract_traffic_reward("签到成功，共 1.25 GB 流量"), "1.25 GB")

    def test_message_without_success_ret_is_not_success(self):
        response = Mock()
        response.text = '{"msg":"已经签到，获得了 100 MB 流量"}'
        response.url = "https://example.com/user/checkin"
        session = Mock()
        session.post.return_value = response

        ok, _, _ = main.checkin(session)

        self.assertFalse(ok)

    @patch.object(main, "checkin")
    @patch.object(main, "login", return_value=(True, "登录成功", {"ret": 1}))
    @patch.object(main, "build_session", return_value=Mock())
    def test_dashboard_already_signed_skips_checkin(self, _build, _login, checkin_mock):
        state = main.DashboardState("signed", True, "主页禁用的签到控件显示“明日再来”")
        with patch.object(main, "inspect_dashboard", return_value=state):
            result = main.sign_one(1, "user@example.com", "secret")

        self.assertTrue(result.ok)
        self.assertEqual(result.stage, "已签到")
        checkin_mock.assert_not_called()

    @patch.object(main.time, "sleep")
    @patch.object(main, "checkin", return_value=(True, "获得 100 MB 流量", {"ret": 1}))
    @patch.object(main, "login", return_value=(True, "登录成功", {"ret": 1}))
    @patch.object(main, "build_session", return_value=Mock())
    def test_api_success_but_dashboard_unsigned_is_failure(
        self, _build, _login, _checkin, _sleep
    ):
        states = [
            main.DashboardState("unsigned", True, "主页显示签到"),
            main.DashboardState("unsigned", True, "主页仍显示签到"),
        ]
        with patch.object(main, "inspect_dashboard", side_effect=states):
            result = main.sign_one(1, "user@example.com", "secret")

        self.assertFalse(result.ok)
        self.assertEqual(result.stage, "签到验证失败")

    @patch.object(main.time, "sleep")
    @patch.object(main, "checkin", return_value=(True, "获得 100 MB 流量", {"ret": 1}))
    @patch.object(main, "login", return_value=(True, "登录成功", {"ret": 1}))
    @patch.object(main, "build_session", return_value=Mock())
    def test_api_success_and_dashboard_signed_is_success(
        self, _build, _login, _checkin, _sleep
    ):
        states = [
            main.DashboardState("unsigned", True, "主页显示签到"),
            main.DashboardState("signed", True, "主页显示已签到"),
        ]
        with patch.object(main, "inspect_dashboard", side_effect=states):
            result = main.sign_one(1, "user@example.com", "secret")

        self.assertTrue(result.ok)
        self.assertEqual(result.stage, "签到并验证")
        self.assertEqual(result.reward, "100 MB")

    @patch.object(main.time, "sleep")
    @patch.object(main, "checkin", return_value=(True, "签到成功，共 256 MB 流量", {"ret": 1}))
    @patch.object(main, "login", return_value=(True, "登录成功", {"ret": 1}))
    @patch.object(main, "build_session", return_value=Mock())
    def test_api_success_and_unknown_dashboard_is_success_with_warning(
        self, _build, _login, _checkin, _sleep
    ):
        states = [
            main.DashboardState("unknown", True, "主页未暴露可识别的签到状态"),
            main.DashboardState("unknown", True, "主页未暴露可识别的签到状态"),
        ]
        with patch.object(main, "inspect_dashboard", side_effect=states):
            result = main.sign_one(1, "user@example.com", "secret")

        self.assertTrue(result.ok)
        self.assertEqual(result.stage, "签到成功（接口确认）")
        self.assertIn("接口已明确确认", result.verification)
        self.assertEqual(result.reward, "256 MB")

    @patch.object(main.time, "sleep")
    @patch.object(main, "checkin", return_value=(False, "您似乎已经签到过了...", {"ret": 0}))
    @patch.object(main, "login", return_value=(True, "登录成功", {"ret": 1}))
    @patch.object(main, "build_session", return_value=Mock())
    def test_already_signed_message_and_unknown_dashboard_remains_failure(
        self, _build, _login, _checkin, _sleep
    ):
        state = main.DashboardState("unknown", True, "主页未暴露可识别的签到状态")
        with patch.object(main, "inspect_dashboard", return_value=state):
            result = main.sign_one(1, "user@example.com", "secret")

        self.assertFalse(result.ok)
        self.assertEqual(result.stage, "签到待确认")


class SmtpConfigurationTests(unittest.TestCase):
    def test_newapi_individual_secrets_override_grouped_secrets(self):
        with (
            patch.object(main, "SMTP_SERVER", "legacy.example.com:465"),
            patch.object(main, "SMTP_ACCOUNT", "legacy@example.com\nlegacy-pass\nlegacy-to@example.com"),
            patch.object(main, "SMTP_HOST_ENV", "smtp.qq.com"),
            patch.object(main, "SMTP_PORT_ENV", "587"),
            patch.object(main, "SMTP_USER_ENV", "new@example.com"),
            patch.object(main, "SMTP_PASS_ENV", "new-pass"),
            patch.object(main, "SMTP_TO_ENV", "new-to@example.com"),
            patch.object(main, "SMTP_FROM_ENV", "notice@example.com"),
            patch.object(main, "MAIL_TO_ENV", "old-to@example.com"),
        ):
            config = main.resolve_smtp_config()

        self.assertEqual(
            config,
            (
                "smtp.qq.com",
                587,
                False,
                "new@example.com",
                "new-pass",
                "new-to@example.com",
                "notice@example.com",
            ),
        )

    def test_grouped_smtp_secrets_remain_supported(self):
        with (
            patch.object(main, "SMTP_SERVER", "smtp.qq.com:465"),
            patch.object(main, "SMTP_ACCOUNT", "sender@qq.com\nauth-code\nreceiver@example.com"),
            patch.object(main, "SMTP_HOST_ENV", ""),
            patch.object(main, "SMTP_PORT_ENV", ""),
            patch.object(main, "SMTP_USER_ENV", ""),
            patch.object(main, "SMTP_PASS_ENV", ""),
            patch.object(main, "SMTP_TO_ENV", ""),
            patch.object(main, "SMTP_FROM_ENV", ""),
            patch.object(main, "MAIL_TO_ENV", ""),
        ):
            config = main.resolve_smtp_config()

        self.assertEqual(
            config,
            ("smtp.qq.com", 465, True, "sender@qq.com", "auth-code", "receiver@example.com", "sender@qq.com"),
        )


class PanelDiscoveryTests(unittest.TestCase):
    def test_directory_page_links_yield_panel_hosts(self):
        html = (
            '<a href="https://ikuuu.win/">ikuuu.win</a>'
            '<a href="https://ikuuu.fyi/">ikuuu.fyi</a>'
            '<a href="https://ikuuu.de/">ikuuu.de</a>'
            '<a href="#top">anchor</a>'
        )
        response = Mock(status_code=200, text=html)
        with patch.object(main.requests, "get", return_value=response) as get_mock:
            hosts = main.discover_panel_hosts()

        get_mock.assert_called_once()
        # Directory host ikuuu.de must be filtered out; win + fyi preserved in order.
        self.assertEqual(hosts, ["https://ikuuu.win", "https://ikuuu.fyi"])

    def test_non_ikuuu_links_are_ignored(self):
        html = (
            '<a href="https://example.com/">example</a>'
            '<a href="https://github.com/xKiian/GeekedTest">repo</a>'
            '<a href="https://ikuuu.one/">ikuuu.one</a>'
        )
        response = Mock(status_code=200, text=html)
        with patch.object(main.requests, "get", return_value=response):
            hosts = main.discover_panel_hosts()

        self.assertEqual(hosts, ["https://ikuuu.one"])

    def test_request_failure_returns_empty_list(self):
        with patch.object(main.requests, "get", side_effect=ConnectionError("boom")):
            hosts = main.discover_panel_hosts()

        self.assertEqual(hosts, [])

    def test_http_error_returns_empty_list(self):
        response = Mock(status_code=503, text="")
        with patch.object(main.requests, "get", return_value=response):
            hosts = main.discover_panel_hosts()

        self.assertEqual(hosts, [])

    def test_falls_back_to_plain_text_substring(self):
        html = "Current domain: ikuuu.win (online). Backup: ikuuu.fyi."
        response = Mock(status_code=200, text=html)
        with patch.object(main.requests, "get", return_value=response):
            hosts = main.discover_panel_hosts()

        self.assertEqual(hosts, ["https://ikuuu.win", "https://ikuuu.fyi"])

    @patch.object(main, "discover_panel_hosts", return_value=["https://ikuuu.fyi"])
    @patch.object(main, "probe_panel_api")
    def test_resolve_prefers_discovered_host_when_configured_is_directory(
        self, probe_mock, _discover_mock
    ):
        probe_mock.side_effect = [
            (True, "panel api ok"),
        ]
        result = main.resolve_base_url("https://ikuuu.de")

        self.assertEqual(result, "https://ikuuu.fyi")
        probe_mock.assert_called_once_with("https://ikuuu.fyi")

    @patch.object(main, "discover_panel_hosts", return_value=["https://ikuuu.fyi"])
    @patch.object(main, "probe_panel_api")
    def test_resolve_keeps_configured_when_it_is_a_real_panel(
        self, probe_mock, _discover_mock
    ):
        probe_mock.side_effect = [(True, "panel api ok")]
        result = main.resolve_base_url("https://ikuuu.win")

        self.assertEqual(result, "https://ikuuu.win")
        probe_mock.assert_called_once_with("https://ikuuu.win")


class NotificationTests(unittest.TestCase):
    def test_actions_falls_back_to_smtp_when_resend_fails(self):
        resend_failure = main.DeliveryResult("邮件/Resend", True, False, "HTTP 403")
        smtp_success = main.DeliveryResult("邮件/SMTP", True, True, "投递成功")
        with (
            patch.dict(main.os.environ, {"GITHUB_ACTIONS": "true"}),
            patch.object(main, "RESEND_API_KEY", "re_test"),
            patch.object(main, "MAIL_TO", "receiver@example.com"),
            patch.object(main, "SMTP_HOST", "smtp.qq.com"),
            patch.object(main, "SMTP_USER", "sender@qq.com"),
            patch.object(main, "SMTP_PASS", "auth-code"),
            patch.object(main, "send_email_resend", return_value=resend_failure) as resend,
            patch.object(main, "send_email_smtp", return_value=smtp_success) as smtp,
        ):
            result = main.send_email("标题", "正文", "<p>正文</p>")

        self.assertTrue(result.ok)
        resend.assert_called_once()
        smtp.assert_called_once()

    def test_resend_only_does_not_print_smtp_warning(self):
        success = main.DeliveryResult("邮件/Resend", True, True, "投递成功")
        with (
            patch.dict(main.os.environ, {"GITHUB_ACTIONS": "true"}),
            patch.object(main, "RESEND_API_KEY", "re_test"),
            patch.object(main, "MAIL_TO", "owner@example.com"),
            patch.object(main, "SMTP_HOST", ""),
            patch.object(main, "SMTP_USER", ""),
            patch.object(main, "SMTP_PASS", ""),
            patch.object(main, "SMTP_SERVER", ""),
            patch.object(main, "SMTP_ACCOUNT", ""),
            patch.object(main, "send_email_resend", return_value=success),
            patch("builtins.print") as print_mock,
        ):
            result = main.send_email("标题", "正文", "<p>正文</p>")

        self.assertTrue(result.ok)
        rendered = " ".join(str(call) for call in print_mock.call_args_list)
        self.assertNotIn("SMTP", rendered)

    def test_resend_uses_mail_to_without_smtp_account(self):
        response = Mock(status_code=200, text='{"id":"email_123"}')
        with (
            patch.object(main, "RESEND_API_KEY", "re_test"),
            patch.object(main, "RESEND_FROM", "notice@example.com"),
            patch.object(main, "MAIL_TO", "receiver@example.com"),
            patch.object(main, "SMTP_USER", ""),
            patch.object(main.requests, "post", return_value=response) as post,
        ):
            result = main.send_email_resend("标题", "纯文本", "<b>HTML</b>")

        self.assertTrue(result.ok)
        self.assertEqual(post.call_args.kwargs["json"]["to"], ["receiver@example.com"])
        self.assertEqual(post.call_args.kwargs["json"]["html"], "<b>HTML</b>")

    def test_resend_does_not_reuse_unverified_smtp_sender(self):
        response = Mock(status_code=200, text='{"id":"email_123"}')
        with (
            patch.object(main, "RESEND_API_KEY", "re_test"),
            patch.object(main, "RESEND_FROM", ""),
            patch.object(main, "MAIL_TO", "receiver@example.com"),
            patch.object(main, "SMTP_USER", "sender@qq.com"),
            patch.object(main.requests, "post", return_value=response) as post,
        ):
            result = main.send_email_resend("标题", "纯文本", "<b>HTML</b>")

        self.assertTrue(result.ok)
        self.assertEqual(post.call_args.kwargs["json"]["from"], "onboarding@resend.dev")

    def test_resend_testing_recipient_error_is_actionable(self):
        response = Mock(
            status_code=403,
            text=(
                '{"statusCode":403,"name":"validation_error","message":'
                '"You can only send testing emails to your own email address '
                '(owner@example.com). To send emails to other recipients, please verify a domain"}'
            ),
        )
        with (
            patch.object(main, "RESEND_API_KEY", "re_test"),
            patch.object(main, "RESEND_FROM", ""),
            patch.object(main, "MAIL_TO", "receiver@example.com"),
            patch.object(main.requests, "post", return_value=response),
        ):
            result = main.send_email_resend("标题", "纯文本", "<b>HTML</b>")

        self.assertFalse(result.ok)
        self.assertIn("owner@example.com", result.message)
        self.assertIn("验证域名", result.message)

    def test_serverchan_http_200_with_error_code_is_failure(self):
        response = Mock(status_code=200, ok=True, text='{"code":40001,"message":"bad key"}')
        with (
            patch.object(main, "SCKEY", "test-key"),
            patch.object(main.requests, "post", return_value=response),
        ):
            result = main.send_serverchan("标题", "内容")

        self.assertFalse(result.ok)
        self.assertIn("code=40001", result.message)

    def test_partial_resend_configuration_is_reported_as_failure(self):
        with (
            patch.object(main, "RESEND_API_KEY", "re_test"),
            patch.object(main, "RESEND_FROM", ""),
            patch.object(main, "MAIL_TO", ""),
            patch.object(main, "SMTP_SERVER", ""),
            patch.object(main, "SMTP_ACCOUNT", ""),
            patch.object(main, "SMTP_HOST", ""),
            patch.object(main, "SMTP_USER", ""),
            patch.object(main, "SMTP_PASS", ""),
        ):
            result = main.send_email("标题", "正文", "<p>正文</p>")

        self.assertTrue(result.configured)
        self.assertFalse(result.ok)
        self.assertIn("MAIL_TO", result.message)

    def test_notification_contains_plain_markdown_and_html_layouts(self):
        result = main.AccountResult(
            1,
            "user@example.com",
            True,
            "签到并验证",
            "获得 100 MB 流量",
            "主页显示已签到",
            "100 MB",
        )

        title, plain, markdown, html = main.build_notification([result])

        self.assertIn("[签到成功] 1/1", title)
        self.assertIn("账号明细", plain)
        self.assertIn("### #1 `us***r@example.com`", markdown)
        self.assertIn("<table", html)
        self.assertIn("主页显示已签到", html)
        self.assertIn("本次奖励：100 MB", plain)
        self.assertIn("**本次奖励：** `100 MB`", markdown)
        self.assertIn("本次奖励", html)


if __name__ == "__main__":
    unittest.main()
