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


class CheckinRetryTests(unittest.TestCase):
    def _mock_response(self, text, url="https://ikuuu.foo/user/checkin"):
        resp = Mock()
        resp.text = text
        resp.url = url
        return resp

    @patch.object(main.time, "sleep")
    def test_retries_on_network_error_then_succeeds(self, _sleep):
        session = Mock()
        session.post.side_effect = [
            ConnectionError("boom"),
            self._mock_response('{"ret":1,"msg":"签到成功，获得 100 MB"}'),
        ]
        ok, msg, _ = main.checkin(session)
        self.assertTrue(ok)
        self.assertEqual(session.post.call_count, 2)

    @patch.object(main.time, "sleep")
    def test_retries_on_non_json_then_succeeds(self, _sleep):
        session = Mock()
        session.post.side_effect = [
            self._mock_response("<html>502 Bad Gateway</html>"),
            self._mock_response('{"ret":1,"msg":"签到成功"}'),
        ]
        ok, msg, _ = main.checkin(session)
        self.assertTrue(ok)
        self.assertEqual(session.post.call_count, 2)

    @patch.object(main.time, "sleep")
    def test_does_not_retry_when_redirected_to_login(self, _sleep):
        session = Mock()
        session.post.return_value = self._mock_response(
            "<html>login</html>", url="https://ikuuu.foo/auth/login"
        )
        ok, msg, _ = main.checkin(session)
        self.assertFalse(ok)
        self.assertIn("not logged in", msg)
        self.assertEqual(session.post.call_count, 1)

    @patch.object(main.time, "sleep")
    def test_does_not_retry_on_definitive_failure_ret(self, _sleep):
        session = Mock()
        session.post.return_value = self._mock_response('{"ret":0,"msg":"已经签到"}')
        ok, msg, _ = main.checkin(session)
        self.assertFalse(ok)
        self.assertEqual(session.post.call_count, 1)

    @patch.object(main.time, "sleep")
    def test_exhausts_retries_on_persistent_network_error(self, _sleep):
        session = Mock()
        session.post.side_effect = ConnectionError("boom")
        ok, msg, _ = main.checkin(session)
        self.assertFalse(ok)
        self.assertIn("attempt", msg.lower())
        self.assertEqual(session.post.call_count, main.MAX_CHECKIN_RETRIES)

    @patch.object(main.time, "sleep")
    def test_exhausts_retries_on_persistent_non_json(self, _sleep):
        session = Mock()
        session.post.return_value = self._mock_response("<html>error</html>")
        ok, msg, _ = main.checkin(session)
        self.assertFalse(ok)
        self.assertEqual(session.post.call_count, main.MAX_CHECKIN_RETRIES)



class PanelDiscoveryTests(unittest.TestCase):
    def test_directory_page_links_yield_panel_hosts(self):
        html = (
            '<a href="https://ikuuu.foo/">ikuuu.foo</a>'
            '<a href="https://ikuuu.bar/">ikuuu.bar</a>'
            '<a href="https://ikuuu.li/">ikuuu.li</a>'
            '<a href="#top">anchor</a>'
        )
        response = Mock(status_code=200, text=html)
        with patch.object(main, "_http_get", return_value=response) as get_mock:
            hosts = main.discover_panel_hosts()

        get_mock.assert_called_once()
        # Directory host ikuuu.li must be filtered out; foo + bar preserved in order.
        self.assertEqual(hosts, ["https://ikuuu.foo", "https://ikuuu.bar"])

    def test_non_ikuuu_links_are_ignored(self):
        html = (
            '<a href="https://example.com/">example</a>'
            '<a href="https://github.com/xKiian/GeekedTest">repo</a>'
            '<a href="https://ikuuu.foo/">ikuuu.foo</a>'
        )
        response = Mock(status_code=200, text=html)
        with patch.object(main, "_http_get", return_value=response):
            hosts = main.discover_panel_hosts()

        self.assertEqual(hosts, ["https://ikuuu.foo"])

    def test_request_failure_returns_empty_list(self):
        with patch.object(main, "_http_get", side_effect=ConnectionError("boom")):
            hosts = main.discover_panel_hosts()

        self.assertEqual(hosts, [])

    def test_http_error_returns_empty_list(self):
        response = Mock(status_code=503, text="")
        with patch.object(main, "_http_get", return_value=response):
            hosts = main.discover_panel_hosts()

        self.assertEqual(hosts, [])

    def test_falls_back_to_plain_text_substring(self):
        html = "Current domain: ikuuu.foo (online). Backup: ikuuu.bar."
        response = Mock(status_code=200, text=html)
        with patch.object(main, "_http_get", return_value=response):
            hosts = main.discover_panel_hosts()

        self.assertEqual(hosts, ["https://ikuuu.foo", "https://ikuuu.bar"])

    @patch.object(main, "discover_panel_hosts", return_value=["https://ikuuu.bar"])
    @patch.object(main, "probe_panel_api")
    def test_resolve_prefers_discovered_host_when_configured_is_directory(
        self, probe_mock, _discover_mock
    ):
        probe_mock.side_effect = [
            (True, "panel api ok"),
        ]
        result = main.resolve_base_url("https://ikuuu.li")

        self.assertEqual(result, "https://ikuuu.bar")
        probe_mock.assert_called_once_with("https://ikuuu.bar")

    @patch.object(main, "discover_panel_hosts", return_value=["https://ikuuu.bar"])
    @patch.object(main, "probe_panel_api")
    def test_resolve_keeps_configured_when_it_is_a_real_panel(
        self, probe_mock, _discover_mock
    ):
        probe_mock.side_effect = [(True, "panel api ok")]
        result = main.resolve_base_url("https://ikuuu.foo")

        self.assertEqual(result, "https://ikuuu.foo")
        probe_mock.assert_called_once_with("https://ikuuu.foo")



class NotificationTests(unittest.TestCase):
    def test_notification_contains_markdown_layout(self):
        result = main.AccountResult(
            1,
            "user@example.com",
            True,
            "签到并验证",
            "获得 100 MB 流量",
            "主页显示已签到",
            "100 MB",
        )

        title, markdown = main.build_notification([result])

        self.assertIn("[签到成功] 1/1", title)
        self.assertIn("### #1 `us***r@example.com`", markdown)
        self.assertIn("主页显示已签到", markdown)
        self.assertIn("**本次奖励：** `100 MB`", markdown)

class CaptchaSolverTests(unittest.TestCase):
    def test_extract_seccode_from_seccode_dict(self):
        verify_data = {
            "result": "success",
            "seccode": {
                "lot_number": "lot1",
                "captcha_output": "out1",
                "pass_token": "token1",
                "gen_time": "1234",
            },
        }
        result = main._extract_seccode(verify_data)
        self.assertEqual(result["lot_number"], "lot1")
        self.assertEqual(result["captcha_output"], "out1")
        self.assertEqual(result["pass_token"], "token1")
        self.assertEqual(result["gen_time"], "1234")

    def test_extract_seccode_from_flat_fields(self):
        verify_data = {
            "result": "success",
            "lot_number": "lot2",
            "captcha_output": "out2",
            "pass_token": "token2",
            "gen_time": "5678",
        }
        result = main._extract_seccode(verify_data)
        self.assertEqual(result["captcha_output"], "out2")
        self.assertEqual(result["pass_token"], "token2")

    def test_extract_seccode_returns_none_when_missing(self):
        self.assertIsNone(main._extract_seccode({"result": "fail"}))
        self.assertIsNone(main._extract_seccode({}))

    def test_parse_jsonp_standard(self):
        raw = 'geetest_123({"status":"success","data":{"data":{"result":"success"}}})'
        result = main._parse_jsonp(raw, "geetest_123")
        self.assertEqual(result["status"], "success")

    def test_parse_jsonp_with_semicolon(self):
        raw = 'cb({"data":{"data":{}}});'
        result = main._parse_jsonp(raw, "cb")
        self.assertIn("data", result)

    def test_generate_w_produces_nonempty_string(self):
        data = {
            "lot_number": "1234567890123456789012345678901234567890",
            "pow_detail": {"hashfunc": "md5", "version": 1, "bits": 4, "datetime": "1"},
            "pt": "1",
        }
        w = main._GeeSigner.generate_w(data, "test_captcha_id", "ai")
        self.assertIsInstance(w, str)
        self.assertTrue(len(w) > 50)

    def _make_fake_get(self, load_payload, verify_payload):
        import json as _json
        def fake_get(url, params, timeout=15):
            cb = params.get("callback", "cb")
            if "/load" in url:
                return Mock(text=cb + "(" + _json.dumps(load_payload) + ")")
            return Mock(text=cb + "(" + _json.dumps(verify_payload) + ")")
        return fake_get

    def test_solve_success_on_first_verify(self):
        solver = main.GeetestSolver("cid", "ai")
        lot = "a1b2c3d4e5f6789012345678abcdef01"
        load_payload = {"data": {"lot_number": lot, "captcha_type": "ai", "pow_detail": {"hashfunc": "md5", "version": 1, "bits": 4, "datetime": "1"}, "payload": "p1", "process_token": "t1", "pt": "1"}}
        verify_payload = {"data": {"result": "success", "seccode": {"lot_number": lot, "captcha_output": "out", "pass_token": "tok", "gen_time": "99"}}}
        solver._get = self._make_fake_get(load_payload, verify_payload)
        result = solver.solve(max_attempts=3, max_duration_seconds=10)
        self.assertEqual(result["lot_number"], lot)
        self.assertEqual(result["captcha_output"], "out")

    def test_solve_loops_on_continue_then_success(self):
        solver = main.GeetestSolver("cid", "ai")
        lot1 = "a1b2c3d4e5f6789012345678abcdef01"
        lot2 = "b2c3d4e5f6789012345678abcdef012"
        import json as _json

        load1 = {"data": {"lot_number": lot1, "captcha_type": "ai", "pow_detail": {"hashfunc": "md5", "version": 1, "bits": 4, "datetime": "1"}, "payload": "p1", "process_token": "t1", "pt": "1"}}
        verify1 = {"data": {"result": "continue", "lot_number": lot2, "payload": "p2", "process_token": "t2", "pt": "1", "payload_protocol": "1"}}
        load2 = {"data": {"lot_number": lot2, "captcha_type": "ai", "pow_detail": {"hashfunc": "md5", "version": 1, "bits": 4, "datetime": "1"}, "payload": "p2", "process_token": "t2", "pt": "1"}}
        verify2 = {"data": {"result": "success", "seccode": {"lot_number": lot2, "captcha_output": "out2", "pass_token": "tok2", "gen_time": "88"}}}

        responses = [load1, verify1, load2, verify2]

        def fake_get(url, params, timeout=15):
            cb = params.get("callback", "cb")
            payload = responses.pop(0)
            return Mock(text=cb + "(" + _json.dumps(payload) + ")")

        solver._get = fake_get
        result = solver.solve(max_attempts=10, max_duration_seconds=30)
        self.assertEqual(result["lot_number"], lot2)
        self.assertEqual(result["captcha_output"], "out2")

    def test_solve_raises_when_exhausted(self):
        solver = main.GeetestSolver("cid", "ai")
        lot = "a1b2c3d4e5f6789012345678abcdef01"
        load_payload = {"data": {"lot_number": lot, "captcha_type": "ai", "pow_detail": {"hashfunc": "md5", "version": 1, "bits": 4, "datetime": "1"}, "payload": "p", "process_token": "t", "pt": "1"}}
        verify_payload = {"data": {"result": "continue", "lot_number": lot, "payload": "p", "process_token": "t", "pt": "1"}}
        solver._get = self._make_fake_get(load_payload, verify_payload)
        with self.assertRaises(RuntimeError):
            solver.solve(max_attempts=2, max_duration_seconds=5)


if __name__ == "__main__":
    unittest.main()
