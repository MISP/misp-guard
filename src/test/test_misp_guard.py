import pytest
import json
from mitmproxy.test import tflow
from mitmproxy.test import taddons
from mitmproxy.test import tutils
from mitmproxy.http import Headers
from mitmproxy import connection
from mitmproxy.proxy import server_hooks
from .. import mispguard


def load_pull_scenarios():
    with open("./test/test_pull_scenarios.json", "r") as f:
        scenarios = json.loads(f.read())
    return scenarios


def load_push_scenarios():
    with open("./test/test_push_scenarios.json", "r") as f:
        scenarios = json.loads(f.read())
    return scenarios


def mispguard_server_hooks_data(host: str, port: int):
    """
    Builds the `server_connect` hook data for the given destination.
    """
    server = connection.Server(address=(host, port))
    return server_hooks.ServerConnectionHookData(server=server, client=connection.Client(
        peername=("10.0.0.1", 22), sockname=("", 0)
    ))


class TestMispGuard:
    @pytest.fixture(autouse=True)
    def mispguard_addons(self):
        """
        Stops the configuration file watcher of the addons instantiated by the
        tests, the watchers would otherwise pile up for the whole session and
        exhaust the inotify instances available to the user.
        """
        self.addons = []
        yield
        for addon in self.addons:
            addon.done()

    def load_mispguard(self) -> mispguard.MispGuard:
        mg = mispguard.MispGuard()
        self.addons.append(mg)

        with taddons.context(mg) as tctx:
            tctx.configure(mg, config="./test/test_config.json")
            self.tctx = tctx

            return mg

    @pytest.mark.asyncio
    async def test_reject_non_minimal_events_index(self, caplog):
        """
        Test that when requesting /events/index endpoint, the request is rejected if the search filter minimal:1 is not set.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        events_index_req = tutils.treq(
            port=443,
            host="instance1-comp1.com",
            path="/events/index",
            method=b"POST",
            headers=Headers(content_type="application/json"),
            content=b'{"minimal":0, "published":1}',
        )

        flow = tflow.tflow(req=events_index_req)
        flow.client_conn.peername = ("20.0.0.2", "22")
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "{'minimal': 1, 'published': 1} is required for /events/index requests"
            in caplog.text
        )
        assert (
            "request blocked: [POST]/events/index - {'minimal': 1, 'published': 1} is required for /events/index requests"
            in caplog.text
        )
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_reject_non_minimal_galaxy_clusters_rest_search(self, caplog):
        """
        Test that when requesting /galaxy_clusters/restSearch endpoint, the request is rejected if the search filter minimal:1 is not set.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        events_index_req = tutils.treq(
            port=443,
            host="instance1-comp1.com",
            path="/galaxy_clusters/restSearch",
            method=b"POST",
            headers=Headers(content_type="application/json"),
            content=b'{"minimal":0, "published":1}',
        )

        flow = tflow.tflow(req=events_index_req)
        flow.client_conn.peername = ("20.0.0.2", "22")
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "{'minimal': 1, 'published': 1} is required for /galaxy_clusters/restSearch requests"
            in caplog.text
        )
        assert (
            "request blocked: [POST]/galaxy_clusters/restSearch - {'minimal': 1, 'published': 1} is required for /galaxy_clusters/restSearch requests"
            in caplog.text
        )
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_non_allowed_endpoint_is_blocked(self, caplog):
        caplog.set_level("INFO")
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

        assert "MispGuard initialized" in caplog.text
        assert "rejecting non allowed request to /users" in caplog.text
        assert "request blocked: [GET]/users - endpoint not allowed" in caplog.text
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_sync_auth_key_refresh_is_allowed_if_enabled(self, caplog):
        """
        Test that [POST]/users/resetauthkey/me is allowed if the destination
        instance has `allow_sync_auth_key_refresh` enabled.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        reset_auth_key_req = tutils.treq(
            port=443,
            host="instance1-comp1.com",
            path="/users/resetauthkey/me",
            method=b"POST",
        )

        flow = tflow.tflow(req=reset_auth_key_req)
        flow.client_conn.peername = ("20.0.0.2", "22")
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert "received request - [POST]/users/resetauthkey/me" in caplog.text
        assert flow.response is None

    @pytest.mark.asyncio
    async def test_sync_auth_key_refresh_is_blocked_if_not_enabled(self, caplog):
        """
        Test that [POST]/users/resetauthkey/me is blocked if the destination
        instance does not have `allow_sync_auth_key_refresh` enabled.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        reset_auth_key_req = tutils.treq(
            port=443,
            host="instance2-comp1.com",
            path="/users/resetauthkey/me",
            method=b"POST",
        )

        flow = tflow.tflow(req=reset_auth_key_req)
        flow.client_conn.peername = ("20.0.0.2", "22")
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "endpoint /users/resetauthkey/me is not enabled for instance instance_1_2, "
            "set `allow_sync_auth_key_refresh: true` to allow it" in caplog.text
        )
        assert (
            "request blocked: [POST]/users/resetauthkey/me - endpoint not allowed"
            in caplog.text
        )
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_sync_auth_key_refresh_other_user_is_blocked(self, caplog):
        """
        Test that only the `me` auth key can be refreshed, even if the
        destination instance has `allow_sync_auth_key_refresh` enabled.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        reset_auth_key_req = tutils.treq(
            port=443,
            host="instance1-comp1.com",
            path="/users/resetauthkey/1",
            method=b"POST",
        )

        flow = tflow.tflow(req=reset_auth_key_req)
        flow.client_conn.peername = ("20.0.0.2", "22")
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert "rejecting non allowed request to /users/resetauthkey/1" in caplog.text
        assert (
            "request blocked: [POST]/users/resetauthkey/1 - endpoint not allowed"
            in caplog.text
        )
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_allowed_domain_from_unknown_src_is_blocked(self, caplog):
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()
        test_path = "/torlist/?exit"

        event_view_req = tutils.treq(
            port=443,
            host="snort-org-site.s3.amazonaws.com",
            path=test_path,
            method=b"GET",
        )

        flow = tflow.tflow(req=event_view_req)
        flow.client_conn.peername = ("123.123.123.123", "123")
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "source host 123.123.123.123 does not exist in instances hosts mapping"
            in caplog.text
        )
        assert (
            "request blocked: [GET]"
            + test_path
            + " - source host 123.123.123.123 does not exist in instances hosts mapping"
            in caplog.text
        )
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_allowed_domain_from_known_src_is_allowed(self, caplog):
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        event_view_req = tutils.treq(
            port=443,
            host="snort-org-site.s3.amazonaws.com",
            path="/test.txt",
            method=b"GET",
        )

        event_view_resp = tutils.tresp(status_code=200)

        flow = tflow.tflow(req=event_view_req, resp=event_view_resp)
        flow.client_conn.peername = ("20.0.0.2", "22")
        mispguard.request(flow)
        mispguard.response(flow)

        assert "MispGuard initialized" in caplog.text
        assert "request from allowed url - skipping further processing" in caplog.text
        assert "response from allowed url - skipping further processing" in caplog.text
        assert "domain snort-org-site.s3.amazonaws.com was allowed by the allowlist" in caplog.text
        assert flow.response.status_code == 200

    @pytest.mark.asyncio
    async def test_allowed_url_from_unknown_src_is_blocked(self, caplog):
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()
        test_path = "/torlist/?exit"

        event_view_req = tutils.treq(
            port=443,
            host="www.dan.me.uk",
            path=test_path,
            method=b"GET",
        )

        flow = tflow.tflow(req=event_view_req)
        flow.client_conn.peername = ("123.123.123.123", "123")
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "source host 123.123.123.123 does not exist in instances hosts mapping"
            in caplog.text
        )
        assert (
            "request blocked: [GET]"
            + test_path
            + " - source host 123.123.123.123 does not exist in instances hosts mapping"
            in caplog.text
        )
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_allowed_url_from_known_src_is_allowed(self, caplog):
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        event_view_req = tutils.treq(
            port=443,
            host="www.dan.me.uk",
            path="/torlist/?exit",
            method=b"GET",
        )

        event_view_resp = tutils.tresp(status_code=200)

        flow = tflow.tflow(req=event_view_req, resp=event_view_resp)
        flow.client_conn.peername = ("20.0.0.2", "22")
        mispguard.request(flow)
        mispguard.response(flow)

        assert "MispGuard initialized" in caplog.text
        assert "request from allowed url - skipping further processing" in caplog.text
        assert "response from allowed url - skipping further processing" in caplog.text
        assert "url http://www.dan.me.uk:443/torlist/?exit was allowed by the allowlist" in caplog.text
        assert flow.response.status_code == 200

    @pytest.mark.asyncio
    async def test_pull_event_head_passthrough(self):
        mispguard = self.load_mispguard()

        event_view_req = tutils.treq(
            port=443,
            host="instance1-comp1.com",
            path="/events/view/385283a1-b5e0-4e10-a532-dce11c365a56",
            method=b"HEAD",
        )

        event_view_resp = tutils.tresp(status_code=200)

        flow = tflow.tflow(req=event_view_req, resp=event_view_resp)
        flow.client_conn.peername = ("20.0.0.2", "22")
        mispguard.request(flow)
        mispguard.response(flow)

        assert flow.response.status_code == 200

    @pytest.mark.asyncio
    async def test_pull_event_empty_response_invalid_json(self, caplog):
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        event_view_req = tutils.treq(
            port=443,
            host="instance1-comp1.com",
            path="/events/view/385283a1-b5e0-4e10-a532-dce11c365a56/deleted[]:0/deleted[]:1/excludeGalaxy:1/includeEventCorrelations:0/includeFeedCorrelations:0/includeWarninglistHits:0/excludeLocalTags:1",
            method=b"GET",
        )

        event_view_resp = tutils.tresp(status_code=200)

        flow = tflow.tflow(req=event_view_req, resp=event_view_resp)
        flow.client_conn.peername = ("20.0.0.2", "22")
        mispguard.request(flow)
        mispguard.response(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "request blocked: [GET]/events/view/385283a1-b5e0-4e10-a532-dce11c365a56/deleted[]:0/deleted[]:1/excludeGalaxy:1/includeEventCorrelations:0/includeFeedCorrelations:0/includeWarninglistHits:0/excludeLocalTags:1 - invalid JSON body"
            in caplog.text
        )

        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_pull_unknown_src_host(self, caplog):
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        event_view_req = tutils.treq(
            port=443,
            host="instance1-comp1.com",
            path="/events/view/385283a1-b5e0-4e10-a532-dce11c365a56/deleted[]:0/deleted[]:1/excludeGalaxy:1/includeEventCorrelations:0/includeFeedCorrelations:0/includeWarninglistHits:0/excludeLocalTags:1",
            method=b"GET",
        )

        flow = tflow.tflow(req=event_view_req)
        flow.client_conn.peername = ("90.0.0.1", "22")
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "request blocked: [GET]/events/view/385283a1-b5e0-4e10-a532-dce11c365a56/deleted[]:0/deleted[]:1/excludeGalaxy:1/includeEventCorrelations:0/includeFeedCorrelations:0/includeWarninglistHits:0/excludeLocalTags:1 - source host 90.0.0.1 does not exist in instances hosts mapping"
            in caplog.text
        )

        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_pull_unknown_dst_host(self, caplog):
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        mock_request = tutils.treq(
            port=443,
            host="instance99-comp1.com",
            path="/events/view/385283a1-b5e0-4e10-a532-dce11c365a56/deleted[]:0/deleted[]:1/excludeGalaxy:1/includeEventCorrelations:0/includeFeedCorrelations:0/includeWarninglistHits:0/excludeLocalTags:1",
            method=b"GET",
        )

        flow = tflow.tflow(req=mock_request)
        flow.client_conn.peername = ("10.0.0.1", "22")
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "request blocked: [GET]/events/view/385283a1-b5e0-4e10-a532-dce11c365a56/deleted[]:0/deleted[]:1/excludeGalaxy:1/includeEventCorrelations:0/includeFeedCorrelations:0/includeWarninglistHits:0/excludeLocalTags:1 - destination host instance99-comp1.com does not exist in instances hosts mapping"
            in caplog.text
        )

        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_dst_port_not_allowed(self, caplog):
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        mock_request = tutils.treq(
            port=4444,
            host="instance1-comp1.com",
            path="/users/view/me.json",
            method=b"GET",
        )

        flow = tflow.tflow(req=mock_request)
        flow.client_conn.peername = ("20.0.0.2", "22")
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "request blocked: [GET]/users/view/me.json - destination port is not allowed"
            in caplog.text
        )

        assert flow.response.status_code == 403

    def feed_flow(self, path: str, fixture_file: str = None, status_code: int = 200,
                  host: str = "feed1.com", port: int = 443, method: bytes = b"GET",
                  client_ip: str = "10.0.0.1"):
        """
        Builds a feed fetch flow, optionally with the response body loaded from
        a fixture file.
        """
        feed_req = tutils.treq(port=port, host=host, path=path, method=method)

        content = b""
        if fixture_file is not None:
            with open(fixture_file, "rb") as f:
                content = f.read()

        feed_resp = tutils.tresp(
            status_code=status_code,
            headers=Headers(content_type="application/json"),
            content=content,
        )

        flow = tflow.tflow(req=feed_req, resp=feed_resp)
        flow.client_conn.peername = (client_ip, "22")

        return flow

    @pytest.mark.asyncio
    async def test_feed_manifest_blocked_events_are_removed(self, caplog):
        """
        Test that the feed events matching a block rule are removed from the
        feed manifest.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        flow = self.feed_flow(
            "/doc/misp/feed-osint/manifest.json",
            "./test/fixtures/test_feed_manifest.json",
        )
        mispguard.request(flow)
        mispguard.response(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "received feed request - [GET]/doc/misp/feed-osint/manifest.json"
            in caplog.text
        )
        assert (
            "event 1cc7bcb1-a0f0-4c2e-8c1c-b3e0b9f0a002 removed from the `feed_1` "
            "feed manifest - event has blocked tag: tlp:red" in caplog.text
        )
        assert "1 of 3 events removed from the `feed_1` feed manifest" in caplog.text
        assert flow.response.status_code == 200

        # the rewritten body must stay consistent with the response headers
        assert flow.response.headers["content-length"] == str(
            len(flow.response.raw_content)
        )

        manifest = json.loads(flow.response.text)
        assert list(manifest.keys()) == [
            "1cc7bcb1-a0f0-4c2e-8c1c-b3e0b9f0a001",
            "1cc7bcb1-a0f0-4c2e-8c1c-b3e0b9f0a003",
        ]

    @pytest.mark.asyncio
    async def test_feed_manifest_non_blocked_events_are_untouched(self, caplog):
        """
        Test that a feed manifest without any blocked event is passed through
        unmodified.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        with open("./test/fixtures/test_feed_manifest.json", "rb") as f:
            fixture = f.read()

        # `feed_2` has no blocked tags and allows tlp:clear/tlp:white, the
        # tlp:red event of the fixture is dropped by the required taxonomy check
        manifest = json.loads(fixture)
        del manifest["1cc7bcb1-a0f0-4c2e-8c1c-b3e0b9f0a002"]

        feed_req = tutils.treq(
            port=443, host="feed2.com", path="/feeds/misp/manifest.json", method=b"GET"
        )
        feed_resp = tutils.tresp(
            status_code=200,
            headers=Headers(content_type="application/json"),
            content=json.dumps(manifest).encode(),
        )
        flow = tflow.tflow(req=feed_req, resp=feed_resp)
        flow.client_conn.peername = ("10.0.0.1", "22")

        mispguard.request(flow)
        mispguard.response(flow)

        assert "MispGuard initialized" in caplog.text
        assert "removed from the `feed_2` feed manifest" not in caplog.text
        assert flow.response.status_code == 200
        assert json.loads(flow.response.text) == manifest

    @pytest.mark.asyncio
    async def test_feed_manifest_required_taxonomies(self, caplog):
        """
        Test that the feed manifest required taxonomies rules are checked on the
        event metadata.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        feed_req = tutils.treq(
            port=443, host="feed2.com", path="/feeds/misp/manifest.json", method=b"GET"
        )
        feed_resp = tutils.tresp(
            status_code=200,
            headers=Headers(content_type="application/json"),
            content=json.dumps(
                {
                    "1cc7bcb1-a0f0-4c2e-8c1c-b3e0b9f0a004": {
                        "info": "OSINT - event without the required taxonomy",
                        "Tag": [{"name": "type:OSINT"}],
                    }
                }
            ).encode(),
        )
        flow = tflow.tflow(req=feed_req, resp=feed_resp)
        flow.client_conn.peername = ("10.0.0.1", "22")

        mispguard.request(flow)
        mispguard.response(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "event 1cc7bcb1-a0f0-4c2e-8c1c-b3e0b9f0a004 removed from the `feed_2` "
            "feed manifest - event is missing required taxonomy: tlp" in caplog.text
        )
        assert flow.response.status_code == 200
        assert json.loads(flow.response.text) == {}

    @pytest.mark.asyncio
    async def test_feed_event_non_blocked(self, caplog):
        """
        Test that a feed event not matching any block rule is passed through.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        flow = self.feed_flow(
            "/doc/misp/feed-osint/1cc7bcb1-a0f0-4c2e-8c1c-b3e0b9f0a001.json",
            "./test/fixtures/test_feed_event_non-blocked.json",
        )
        mispguard.request(flow)
        mispguard.response(flow)

        assert "MispGuard initialized" in caplog.text
        assert "request blocked" not in caplog.text
        assert flow.response.status_code == 200

    @pytest.mark.asyncio
    async def test_feed_event_blocked_attribute_type(self, caplog):
        """
        Test that a feed event matching a block rule is blocked.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        flow = self.feed_flow(
            "/doc/misp/feed-osint/1cc7bcb1-a0f0-4c2e-8c1c-b3e0b9f0a003.json",
            "./test/fixtures/test_feed_event_blocked_attribute_type.json",
        )
        mispguard.request(flow)
        mispguard.response(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "request blocked: [GET]/doc/misp/feed-osint/"
            "1cc7bcb1-a0f0-4c2e-8c1c-b3e0b9f0a003.json - attribute with a blocked "
            "type: email" in caplog.text
        )
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_feed_event_signature_passthrough(self, caplog):
        """
        Test that the signature of a protected feed event is passed through.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        signature = (
            b"-----BEGIN PGP SIGNATURE-----\n\nc2lnbmF0dXJl\n"
            b"-----END PGP SIGNATURE-----\n"
        )

        feed_req = tutils.treq(
            port=443,
            host="feed1.com",
            path="/doc/misp/feed-osint/1cc7bcb1-a0f0-4c2e-8c1c-b3e0b9f0a001.asc",
            method=b"GET",
        )
        feed_resp = tutils.tresp(
            status_code=200,
            headers=Headers(content_type="text/plain"),
            content=signature,
        )
        flow = tflow.tflow(req=feed_req, resp=feed_resp)
        flow.client_conn.peername = ("10.0.0.1", "22")

        mispguard.request(flow)
        mispguard.response(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "received feed request - [GET]/doc/misp/feed-osint/"
            "1cc7bcb1-a0f0-4c2e-8c1c-b3e0b9f0a001.asc" in caplog.text
        )
        assert "`feed_1` feed event signature response, passthrough" in caplog.text
        assert "request blocked" not in caplog.text
        assert flow.response.status_code == 200
        assert flow.response.content == signature

    @pytest.mark.asyncio
    async def test_feed_signature_of_non_event_is_blocked(self, caplog):
        """
        Test that only the signature of an event can be fetched.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        flow = self.feed_flow("/doc/misp/feed-osint/manifest.asc")
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "rejecting non allowed feed request to /doc/misp/feed-osint/manifest.asc"
            in caplog.text
        )
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_feed_cache_is_blocked_if_not_enabled(self, caplog):
        """
        Test that the feed cache is not fetchable if the feed does not have
        `allow_caching` enabled.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        flow = self.feed_flow("/doc/misp/feed-osint/hashes.csv")
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "endpoint /doc/misp/feed-osint/hashes.csv is not enabled for the `feed_1` "
            "feed, set `allow_caching: true` to allow it" in caplog.text
        )
        assert (
            "request blocked: [GET]/doc/misp/feed-osint/hashes.csv - endpoint not "
            "allowed" in caplog.text
        )
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_feed_cache_is_allowed_if_enabled(self, caplog):
        """
        Test that the feed cache is fetched as is if the feed has
        `allow_caching` enabled, its content can not be filtered.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        cache = (
            b"1cc7bcb1a0f04c2e8c1cb3e0b9f0a001,1cc7bcb1-a0f0-4c2e-8c1c-b3e0b9f0a001\n"
            b"1cc7bcb1a0f04c2e8c1cb3e0b9f0a002,1cc7bcb1-a0f0-4c2e-8c1c-b3e0b9f0a002\n"
        )

        feed_req = tutils.treq(
            port=443, host="feed2.com", path="/feeds/misp/hashes.csv", method=b"GET"
        )
        feed_resp = tutils.tresp(
            status_code=200,
            headers=Headers(content_type="text/csv"),
            content=cache,
        )
        flow = tflow.tflow(req=feed_req, resp=feed_resp)
        flow.client_conn.peername = ("10.0.0.1", "22")

        mispguard.request(flow)
        mispguard.response(flow)

        assert "MispGuard initialized" in caplog.text
        assert "received feed request - [GET]/feeds/misp/hashes.csv" in caplog.text
        assert "`feed_2` feed cache response, passthrough" in caplog.text
        assert "request blocked" not in caplog.text
        assert flow.response.status_code == 200
        assert flow.response.content == cache

    @pytest.mark.asyncio
    async def test_feed_cache_wrong_method_is_blocked(self, caplog):
        """
        Test that the feed cache can only be fetched with a GET request.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        flow = self.feed_flow("/feeds/misp/hashes.csv", host="feed2.com", method=b"POST")
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "rejecting non allowed feed request to /feeds/misp/hashes.csv"
            in caplog.text
        )
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_feed_non_allowed_endpoint_is_blocked(self, caplog):
        """
        Test that only the manifest and the event files of a feed can be fetched.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        flow = self.feed_flow("/doc/misp/feed-osint/hashes.txt")
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "rejecting non allowed feed request to /doc/misp/feed-osint/hashes.txt"
            in caplog.text
        )
        assert (
            "request blocked: [GET]/doc/misp/feed-osint/hashes.txt - endpoint not "
            "allowed" in caplog.text
        )
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_feed_request_from_unknown_src_host_is_blocked(self, caplog):
        """
        Test that only the configured instances can fetch a feed.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        flow = self.feed_flow(
            "/doc/misp/feed-osint/manifest.json",
            "./test/fixtures/test_feed_manifest.json",
            client_ip="99.99.99.99",
        )
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "request blocked: [GET]/doc/misp/feed-osint/manifest.json - source host "
            "99.99.99.99 does not exist in instances hosts mapping" in caplog.text
        )
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_feed_request_to_non_feed_path_is_blocked(self, caplog):
        """
        Test that a request to a feed host outside of the configured feed url is
        blocked as any other non sync related request.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        flow = self.feed_flow("/doc/misp/other-feed/manifest.json")
        mispguard.request(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "destination host feed1.com does not exist in instances hosts mapping"
            in caplog.text
        )
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_feed_non_200_response_passthrough(self, caplog):
        """
        Test that a feed response without event data is passed through.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        flow = self.feed_flow(
            "/doc/misp/feed-osint/manifest.json", status_code=304
        )
        mispguard.request(flow)
        mispguard.response(flow)

        assert "MispGuard initialized" in caplog.text
        assert "request blocked" not in caplog.text
        assert flow.response.status_code == 304

    @pytest.mark.asyncio
    async def test_feed_invalid_manifest_is_blocked(self, caplog):
        """
        Test that a feed manifest that is not a JSON document is blocked.
        """
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        feed_req = tutils.treq(
            port=443,
            host="feed1.com",
            path="/doc/misp/feed-osint/manifest.json",
            method=b"GET",
        )
        feed_resp = tutils.tresp(
            status_code=200,
            headers=Headers(content_type="text/html"),
            content=b"<html>not a manifest</html>",
        )
        flow = tflow.tflow(req=feed_req, resp=feed_resp)
        flow.client_conn.peername = ("10.0.0.1", "22")

        mispguard.request(flow)
        mispguard.response(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "request blocked: [GET]/doc/misp/feed-osint/manifest.json - invalid JSON "
            "body" in caplog.text
        )
        assert flow.response.status_code == 403

    @pytest.mark.asyncio
    async def test_feed_host_connection_is_allowed(self, caplog):
        """
        Test that connections to a configured feed host are allowed.
        """
        caplog.set_level("DEBUG")
        mispguard = self.load_mispguard()

        data = mispguard_server_hooks_data("feed1.com", 443)
        mispguard.server_connect(data)
        assert data.server.error is None

        data = mispguard_server_hooks_data("feed1.com", 4444)
        mispguard.server_connect(data)
        assert data.server.error == "connection not allowed."

    @pytest.mark.asyncio
    @pytest.mark.parametrize("scenario", load_pull_scenarios(), ids=lambda s: s["name"])
    async def test_rules_pull(self, scenario: dict, caplog):
        """
        Test that when trying to pull an event with a matching block rule / compartment rule the request returns the correct status code
        """
        caplog.set_level("INFO")
        caplog.clear()
        mispguard = self.load_mispguard()
        event_view_req = tutils.treq(
            host=scenario["host"],
            port=scenario["port"],
            path=scenario["url"],
            method=scenario["method"],
        )

        with open(scenario["fixture_file"], "rb") as f:
            fixture = f.read()

        mock_response = tutils.tresp(
            status_code=200,
            headers=Headers(content_type="application/json"),
            content=fixture,
        )

        flow = tflow.tflow(req=event_view_req, resp=mock_response)
        flow.client_conn.peername = (
            scenario["client"]["ip"],
            scenario["client"]["port"],
        )
        mispguard.request(flow)
        mispguard.response(flow)

        assert (
            flow.response.status_code == scenario["expected_status_code"]
        ), f"Expected status code {scenario['expected_status_code']} but got {flow.response.status_code} for scenario {scenario['name']}"
        assert "MispGuard initialized" in caplog.text
        for expected_log in scenario["expected_logs"]:
            # debug logs
            # print(caplog.text)
            assert (
                expected_log in caplog.text
            ), f"expected log {expected_log} not found for scenario {scenario['name']}"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("scenario", load_push_scenarios(), ids=lambda s: s["name"])
    async def test_rules_push(self, scenario: dict, caplog):
        """
        Test that when trying to push an event with a matching block rule / compartment rule the request returns the correct status code
        """
        caplog.set_level("INFO")
        caplog.clear()
        mispguard = self.load_mispguard()

        with open(scenario["fixture_file"], "rb") as f:
            fixture = f.read()

        event_view_req = tutils.treq(
            host=scenario["host"],
            port=scenario["port"],
            path=scenario["url"],
            method=scenario["method"],
            headers=Headers(content_type="application/json"),
            content=fixture,
        )

        event_view_resp = tutils.tresp(
            status_code=200, headers=Headers(content_type="application/json")
        )

        flow = tflow.tflow(req=event_view_req, resp=event_view_resp)
        flow.client_conn.peername = (
            scenario["client"]["ip"],
            scenario["client"]["port"],
        )
        mispguard.request(flow)
        mispguard.response(flow)

        assert (
            flow.response.status_code == scenario["expected_status_code"]
        ), f"Expected status code {scenario['expected_status_code']} but got {flow.response.status_code} for scenario {scenario['name']}"
        assert "MispGuard initialized" in caplog.text
        for expected_log in scenario["expected_logs"]:
            # print(caplog.text)
            assert (
                expected_log in caplog.text
            ), f"expected log {expected_log} not found for scenario {scenario['name']}"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "scenario",
        [
            "test_event_xuserorguuid-blocked_sharing_group",
            "test_event_xuserorguuid-attribute_blocked_sharing_group",
            "test_event_xuserorguuid-object-attribute_blocked_sharing_group",
        ],
    )
    async def test_pull_XUserOrgUUID_mismatch(self, scenario: str, caplog):
        caplog.set_level("INFO")
        mispguard = self.load_mispguard()

        events_view_req = tutils.treq(
            port=443,
            host="instance1-comp1.com",
            path="/events/view/385283a1-b5e0-4e10-a532-dce11c365a56/deleted[]:0/deleted[]:1/excludeGalaxy:1/includeEventCorrelations:0/includeFeedCorrelations:0/includeWarninglistHits:0/excludeLocalTags:1",
            method=b"GET",
            headers=Headers(content_type="application/json"),
        )

        with open("test/fixtures/" + scenario + ".json", "rb") as f:
            fixture = f.read()

        event_view_resp = tutils.tresp(
            status_code=200,
            headers=Headers(content_type="application/json"),
            content=fixture,
        )

        # should be 87c33ffe-f83c-4eb1-be09-51f767f6fd5a
        event_view_resp.headers["X-UserOrgUUID"] = (
            "8b9661a3-8544-4f8d-94be-cd7ebe87e922"
        )

        flow = tflow.tflow(req=events_view_req, resp=event_view_resp)
        flow.client_conn.peername = ("20.0.0.2", "22")
        mispguard.request(flow)
        mispguard.response(flow)

        assert "MispGuard initialized" in caplog.text
        assert (
            "request blocked: [GET]/events/view/385283a1-b5e0-4e10-a532-dce11c365a56/deleted[]:0/deleted[]:1/excludeGalaxy:1/includeEventCorrelations:0/includeFeedCorrelations:0/includeWarninglistHits:0/excludeLocalTags:1 - user with organisation uuid: 8b9661a3-8544-4f8d-94be-cd7ebe87e922 (X-UserOrgUUID) not in sharing group"
            in caplog.text
        )
        assert flow.response.status_code == 403

    def test_no_config_file(self, caplog) -> mispguard.MispGuard:
        mg = mispguard.MispGuard()
        self.addons.append(mg)
        caplog.set_level("INFO")

        with taddons.context(mg) as tctx:
            try:
                tctx.configure(mg, config="./test/not-found.json")
                self.tctx = tctx
            except SystemExit:
                assert (
                    "failed to load config file, use: `--set config=config.json`"
                    in caplog.text
                )

    def test_invalid_config_file(self, caplog) -> mispguard.MispGuard:
        mg = mispguard.MispGuard()
        self.addons.append(mg)
        caplog.set_level("INFO")

        with taddons.context(mg) as tctx:
            try:
                tctx.configure(mg, config="./test/fixtures/test_invalid_config.json")
                self.tctx = tctx
            except SystemExit:
                assert "failed to load config file: " in caplog.text
