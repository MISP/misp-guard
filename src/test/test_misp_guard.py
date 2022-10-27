import pytest
import json
from mitmproxy.test import tflow
from mitmproxy.test import taddons
from mitmproxy.test import tutils
from mitmproxy.http import Headers
from mitmproxy import connection
from .. import mispguard


def load_pull_scenarios():
    with open("./test/test_pull_scenarios.json", "r") as f:
        scenarios = json.loads(f.read())
    return scenarios


def load_push_scenarios():
    with open("./test/test_push_scenarios.json", "r") as f:
        scenarios = json.loads(f.read())
    return scenarios


class TestMispGuard:
    def load_mispguard(self) -> mispguard.MispGuard:
        mg = mispguard.MispGuard()

        with taddons.context(mg) as tctx:
            tctx.configure(mg, config="./test/test_config.json")
            self.tctx = tctx

            return mg

    @pytest.mark.asyncio
    async def test_reject_non_minimal_events_index(self):
        """
        Test that when requesting /events/index endpoint, the request is rejected if the search filter minimal:1 is not set.
        """

        mispguard = self.load_mispguard()

        events_index_req = tutils.treq(
            port=443,
            host="instance1-comp1.com",
            path="/events/index",
            method=b"POST",
            headers=Headers(content_type="application/json"),
            content=b"{\"minimal\":0, \"published\":1}",
        )

        flow = tflow.tflow(req=events_index_req)
        flow.client_conn.peername = ("20.0.0.2", "22")
        mispguard.request(flow)

        await self.tctx.master.await_log("MispGuard initialized")
        assert self.tctx.master.has_log(
            "{'minimal': 1, 'published': 1} is required for /events/index requests")
        assert self.tctx.master.has_log("request blocked: [POST]/events/index - unexpected error, rejecting request")
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_non_allowed_endpoint_is_blocked(self):
        mispguard = self.load_mispguard()

        event_view_req = tutils.treq(
            port=443,
            host="instance1-comp1.com",
            path="/users",
            method=b"GET",
        )

        flow = tflow.tflow(req=event_view_req)
        flow.client_conn.peername = ("20.0.0.2", "22")
        mispguard.request(flow)

        await self.tctx.master.await_log("MispGuard initialized")
        assert self.tctx.master.has_log("rejecting non allowed request to /users")
        assert self.tctx.master.has_log("request blocked: [GET]/users - endpoint not allowed")
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    @pytest.mark.parametrize("scenario", load_pull_scenarios(), ids=lambda s: s["name"])
    async def test_rules_pull(self, scenario: dict):
        """
        Test that when trying to pull an event with a matching block rule / compartment rule the request returns the correct status code
        """

        mispguard = self.load_mispguard()
        self.tctx.master.clear()
        event_view_req = tutils.treq(
            host=scenario["host"],
            port=scenario["port"],
            path=scenario["url"],
            method=scenario["method"]
        )

        with open(scenario["event_fixture_file"], "rb") as f:
            event = f.read()

        event_view_resp = tutils.tresp(
            status_code=200,
            headers=Headers(content_type="application/json"),
            content=event
        )

        flow = tflow.tflow(req=event_view_req, resp=event_view_resp)
        flow.client_conn.peername = (scenario["client"]["ip"], scenario["client"]["port"])
        mispguard.request(flow)
        mispguard.response(flow)

        assert flow.response.status_code == scenario[
            "expected_status_code"], f"Expected status code {scenario['expected_status_code']} but got {flow.response.status_code} for scenario {scenario['name']}"
        await self.tctx.master.await_log("MispGuard initialized")
        for expected_log in scenario["expected_logs"]:
            self.tctx.master.dump_log()
            assert self.tctx.master.has_log(
                expected_log), f"expected log {expected_log} not found for scenario {scenario['name']}"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("scenario", load_push_scenarios(), ids=lambda s: s["name"])
    async def test_rules_push(self, scenario: dict):
        """
        Test that when trying to push an event with a matching block rule / compartment rule the request returns the correct status code
        """

        mispguard = self.load_mispguard()
        self.tctx.master.clear()

        with open(scenario["event_fixture_file"], "rb") as f:
            event = f.read()

        event_view_req = tutils.treq(
            host=scenario["host"],
            port=scenario["port"],
            path=scenario["url"],
            method=scenario["method"],
            headers=Headers(content_type="application/json"),
            content=event
        )

        event_view_resp = tutils.tresp(
            status_code=200,
            headers=Headers(content_type="application/json")
        )

        flow = tflow.tflow(req=event_view_req, resp=event_view_resp)
        flow.client_conn.peername = (scenario["client"]["ip"], scenario["client"]["port"])
        mispguard.request(flow)
        mispguard.response(flow)

        assert flow.response.status_code == scenario[
            "expected_status_code"], f"Expected status code {scenario['expected_status_code']} but got {flow.response.status_code} for scenario {scenario['name']}"
        await self.tctx.master.await_log("MispGuard initialized")
        for expected_log in scenario["expected_logs"]:
            self.tctx.master.dump_log()
            assert self.tctx.master.has_log(
                expected_log), f"expected log {expected_log} not found for scenario {scenario['name']}"
