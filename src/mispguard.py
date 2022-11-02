"""
This script filters out MISP events based on a set of rules.
The rules are defined in a JSON file.
"""

from functools import lru_cache
from mitmproxy import http, ctx
from jsonschema import validate, Draft202012Validator
import json
import re
from os.path import exists


class ForbiddenException (Exception):
    pass


class MISPHTTPFlow(http.HTTPFlow):
    src_compartment_id: str = None
    dst_compartment_id: str = None
    src_instance_id: str = None
    dst_instance_id: str = None
    is_event: bool = False
    is_shadow_attributes: bool = False
    is_event_index: bool = False
    is_pull: bool = False
    is_push: bool = False


class MispGuard:
    def __init__(self):
        self.config: dict = {}
        self.allowed_endpoints = [
            {
                "regex": r"^\/servers\/getVersion$",
                "methods": [
                    "GET"
                ]
            },
            {
                "regex": r"^\/servers\/postTest$",
                "methods": [
                    "POST"
                ]
            },
            {
                "regex": r"^\/events\/index$",
                "methods": [
                    "POST"
                ]
            },
            {
                "regex": r"^\/events\/filterEventIdsForPush$",
                "methods": [
                    "POST"
                ]
            },
            {
                "regex": r"^\/events\/view\/[\w\-]{36}$",
                "methods": [
                    "HEAD"
                ]
            },
            {
                "regex": r"^\/events\/add.*$",
                "methods": [
                    "POST"
                ]
            },
            {
                "regex": r"^\/events\/edit\/[\w\-]{36}.*$",
                "methods": [
                    "POST"
                ]
            },
            {
                "regex": r"^\/servers\/getAvailableSyncFilteringRules$",
                "methods": [
                    "GET"
                ]
            },
            {
                "regex": r"^\/events\/view.*$",
                "methods": [
                    "GET"
                ]
            },
            {
                "regex": r"^\/shadow_attributes\/index.*$",
                "methods": [
                    "GET"
                ]
            }
        ]

    def configure(self, updated):
        if ctx.options.config and exists(ctx.options.config):
            try:
                with open('config.schema.json', 'r') as file:
                    schema = json.load(file)
                self.config = json.load(open(ctx.options.config))

                validate(
                    instance=self.config,
                    schema=schema,
                    format_checker=Draft202012Validator.FORMAT_CHECKER,
                )

            except Exception as e:
                ctx.log.error("failed to load config file: %s" % str(e))
                exit(1)

        else:
            ctx.log.error("failed to load config file, use: `--set config=config.json`")
            exit(1)
        ctx.log.info("MispGuard initialized")

    def load(self, loader):
        loader.add_option("config", str, "", "MISP Guard configuration file")

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            flow = self.enrich_flow(flow)
            if self.can_reach_compartment(flow) and self.is_allowed_endpoint(flow.request.method, flow.request.path):
                return self.process_request(flow)
        except ForbiddenException as ex:
            ctx.log.error(ex)
            return self.forbidden(flow, str(ex))
        except Exception as ex:
            ctx.log.error(ex)
            return self.forbidden(flow, "unexpected error, rejecting request")

        # filter out requests to the allowed endpoints
        ctx.log.error("rejecting non allowed request to %s" % flow.request.path)
        return self.forbidden(flow)

    def response(self,  flow: http.HTTPFlow) -> None:
        try:
            flow = self.enrich_flow(flow)
            if self.can_reach_compartment(flow):
                return self.process_response(flow)
        except ForbiddenException as ex:
            ctx.log.error(ex)
            return self.forbidden(flow, str(ex))
        except Exception as ex:
            ctx.log.error(ex)
            return self.forbidden(flow, "unexpected error, rejecting response")

    def enrich_flow(self, flow: http.HTTPFlow) -> MISPHTTPFlow:
        ctx.log.debug("enriching http flow")
        flow.__class__ = MISPHTTPFlow
        flow.src_instance_id = self.get_src_instance_id(flow)
        flow.dst_instance_id = self.get_dst_instance_id(flow)
        flow.src_compartment_id = self.config["instances"][flow.src_instance_id]["compartment_id"]
        flow.dst_compartment_id = self.config["instances"][flow.dst_instance_id]["compartment_id"]

        if "/events/view" in flow.request.path:
            flow.is_pull = True
            flow.is_event = True

        if "/shadow_attributes/index" in flow.request.path:
            flow.is_pull = True
            flow.is_shadow_attributes = True

        if "/events/add" in flow.request.path or "/events/edit" in flow.request.path:
            flow.is_push = True
            flow.is_event = True

        if "/events/index" in flow.request.path:
            flow.is_push = True
            flow.is_event_index = True

        return flow

    def process_request(self, flow: MISPHTTPFlow) -> None:
        ctx.log.debug("processing request")
        ctx.log.info("received request - [%s]%s" % (flow.request.method, flow.request.path))

        if flow.is_event and flow.is_push:
            try:
                event = self.get_event_from_message(flow.request)
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            # process block rules
            rules = self.get_rules(flow)
            return self.process_event(rules, event, flow)

        if flow.is_event_index:
            params = flow.request.json()

            if "minimal" not in params or params["minimal"] != 1 or "published" not in params or params["published"] != 1:
                raise ForbiddenException(
                    "{'minimal': 1, 'published': 1} is required for /events/index requests")

    def process_response(self, flow: MISPHTTPFlow) -> None:
        ctx.log.debug("processing response")
        if flow.is_pull and flow.is_event and flow.request.method == "HEAD":
            ctx.log.debug("pull request [HEAD]/events/view passthrough")
            return None  # passthrough

        if flow.is_pull and flow.is_event and flow.request.method != "POST":
            if flow.request.content is None:
                return self.forbidden(flow, "empty request body")

            try:
                event = self.get_event_from_message(flow.response)
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            rules = self.get_rules(flow)
            return self.process_event(rules, event, flow)

        if flow.is_pull and flow.is_shadow_attributes:
            try:
                shadow_attributes = []
                shadow_attributes_aux = self.get_shadow_attributes_from_message(flow.response)
                for shadow_attribute in shadow_attributes_aux:
                    shadow_attributes.append(shadow_attribute["ShadowAttribute"])
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            rules = self.get_rules(flow)
            return self.process_shadow_attributes(rules, shadow_attributes, flow)

    def get_rules(self, flow: MISPHTTPFlow) -> list:
        ctx.log.debug("getting misp-guard instance rules")
        rules = {}
        if flow.is_push:
            rules = self.config["instances"][flow.src_instance_id]
        if flow.is_pull:
            rules = self.config["instances"][flow.dst_instance_id]

        return rules

    def process_event(self, rules: dict, event: dict, flow: MISPHTTPFlow) -> None:
        ctx.log.debug("processing outgoing event: %s" % event["Event"]["info"])

        try:
            self.check_event_level_rules(rules, flow, event)
            self.check_attribute_level_rules(rules, event["Event"]["Attribute"])
            self.check_object_level_rules(rules, event["Event"]["Object"])

        except ForbiddenException as ex:
            return self.forbidden(flow, str(ex))

    def process_shadow_attributes(self, rules: dict, shadow_attributes: dict, flow: MISPHTTPFlow) -> None:
        ctx.log.debug("processing shadow attributes")

        try:
            self.check_attribute_level_rules(rules, shadow_attributes)
        except ForbiddenException as ex:
            return self.forbidden(flow, str(ex))

    def check_event_level_rules(self, rules: dict, flow: MISPHTTPFlow, event: dict) -> None:
        ctx.log.debug("checking event level rules")

        self.check_blocked_event_tags(rules["taxonomies_rules"], event)
        self.check_event_required_taxonomies(rules["taxonomies_rules"], event)
        self.check_blocked_event_distribution_levels(rules["blocked_distribution_levels"], event)
        self.check_blocked_event_sharing_groups_uuids(rules["blocked_sharing_groups_uuids"], event)

    def check_attribute_level_rules(self, rules: dict, attributes: dict) -> None:
        ctx.log.debug("checking attribute level rules")
        for attribute in attributes:
            self.check_blocked_attribute_categories(rules["blocked_attribute_categories"], attribute)
            self.check_blocked_attribute_types(rules["blocked_attribute_types"], attribute)
            self.check_blocked_attribute_distribution_levels(rules["blocked_distribution_levels"], attribute)
            self.check_blocked_attribute_tags(rules["taxonomies_rules"], attribute)
            self.check_attribute_required_taxonomies(rules["taxonomies_rules"], attribute)
            self.check_blocked_attribute_sharing_groups_uuids(rules["blocked_sharing_groups_uuids"], attribute)

            if "ShadowAttribute" in attribute:
                self.check_attribute_level_rules(rules, attribute["ShadowAttribute"])

    def check_object_level_rules(self, rules: dict, objects: dict) -> None:
        for object in objects:
            self.check_blocked_object_distribution_levels(rules["blocked_distribution_levels"], object)
            self.check_blocked_object_sharing_groups_uuids(rules["blocked_sharing_groups_uuids"], object)
            self.check_blocked_object_types(rules["blocked_object_types"], object)
            self.check_attribute_level_rules(rules, object["Attribute"])

    def check_event_required_taxonomies(self, taxonomies_rules: dict, event: dict) -> None:
        ctx.log.debug("checking required event taxonomies")

        if len(taxonomies_rules["required_taxonomies"]) == 0:
            return True

        if not "Tag" in event["Event"]:
            raise ForbiddenException("event is missing required taxonomies")

        for required_taxonomy in taxonomies_rules["required_taxonomies"]:
            ctx.log.debug("checking required taxonomy: %s" % required_taxonomy)
            allowed_tags = taxonomies_rules["allowed_tags"].get(required_taxonomy, [])

            self.check_required_taxonomy_exists(required_taxonomy, event["Event"]["Tag"], allowed_tags)

        return True

    def check_attribute_required_taxonomies(self, taxonomies_rules: dict, attribute: dict) -> None:
        ctx.log.debug("checking required attribute taxonomies")
        if len(taxonomies_rules["required_taxonomies"]) == 0:
            return True

        if not "Tag" in attribute:
            raise ForbiddenException("attribute is missing required taxonomies")

        for required_taxonomy in taxonomies_rules["required_taxonomies"]:
            ctx.log.debug("checking required taxonomy: %s" % required_taxonomy)
            allowed_tags = taxonomies_rules["allowed_tags"].get(required_taxonomy, [])

            self.check_required_taxonomy_exists(required_taxonomy, attribute["Tag"], allowed_tags)

        return True

    def check_required_taxonomy_exists(self, required_taxonomy: str, tags: list, allowed_tags: list = []) -> bool:
        for tag in tags:
            if tag["name"].startswith(required_taxonomy + ":"):
                # if there are allowed tags, check if the tag is allowed
                # otherwise any tag of this taxonomy is ok
                if len(allowed_tags) == 0 or tag["name"] in allowed_tags:
                    return True

        raise ForbiddenException("event is missing required taxonomy: %s" % required_taxonomy)

    def check_blocked_event_tags(self, taxonomies_rules: dict, event: dict) -> None:
        if "Tag" in event["Event"]:
            for tag in event["Event"]["Tag"]:
                if tag["name"] in taxonomies_rules["blocked_tags"]:
                    raise ForbiddenException("event has blocked tag: %s" % tag["name"])

    def check_blocked_event_distribution_levels(self, blocked_distribution_levels: list, event: dict) -> None:
        if event["Event"]["distribution"] in blocked_distribution_levels:
            raise ForbiddenException("event has blocked distribution level: %s" % event["Event"]["distribution"])

    def check_blocked_event_sharing_groups_uuids(self, blocked_sharing_groups_uuids: list, event: dict) -> None:
        if blocked_sharing_groups_uuids and "SharingGroup" in event["Event"]:
            if event["Event"]["SharingGroup"]["uuid"] in blocked_sharing_groups_uuids:
                raise ForbiddenException("event has blocked sharing group uuid: %s" %
                                         event["Event"]["SharingGroup"]["uuid"])

    def check_blocked_attribute_tags(self, taxonomies_rules: dict, attribute: dict) -> None:
        if taxonomies_rules["blocked_tags"] and "Tag" in attribute:
            for tag in attribute["Tag"]:
                if tag["name"] in taxonomies_rules["blocked_tags"]:
                    raise ForbiddenException("attribute with a blocked tag: %s" % tag["name"])

    def check_blocked_attribute_distribution_levels(self, blocked_distribution_levels: list, attribute: dict) -> None:
        if "distribution" in attribute and attribute["distribution"] in blocked_distribution_levels:
            raise ForbiddenException("attribute with a blocked distribution level: %s" % attribute["distribution"])

    def check_blocked_attribute_sharing_groups_uuids(self, blocked_sharing_groups_uuids: list, attribute: dict) -> None:
        if "SharingGroup" in attribute:
            if attribute["SharingGroup"]["uuid"] in blocked_sharing_groups_uuids:
                raise ForbiddenException("attribute with a blocked sharing group uuid: %s" %
                                         attribute["SharingGroup"]["uuid"])

    def check_blocked_attribute_types(self, blocked_attribute_types: list, attribute: dict) -> None:
        if attribute["type"] in blocked_attribute_types:
            raise ForbiddenException("attribute with a blocked type: %s" % attribute["type"])

    def check_blocked_attribute_categories(self, blocked_attribute_categories: list, attribute: dict) -> None:
        if attribute["category"] in blocked_attribute_categories:
            raise ForbiddenException("attribute with a blocked category: %s" % attribute["category"])

    def check_blocked_object_distribution_levels(self, blocked_distribution_levels: list, object: dict) -> None:
        if object["distribution"] in blocked_distribution_levels:
            raise ForbiddenException("object with a blocked distribution level: %s" % object["distribution"])

    def check_blocked_object_sharing_groups_uuids(self, blocked_sharing_groups_uuids: list, object: dict) -> None:
        if "SharingGroup" in object:
            if object["SharingGroup"]["uuid"] in blocked_sharing_groups_uuids:
                raise ForbiddenException("object with a blocked sharing group uuid: %s" %
                                         object["SharingGroup"]["uuid"])

    def check_blocked_object_types(self, blocked_object_types: list, object: dict) -> None:
        if object["name"] in blocked_object_types:
            raise ForbiddenException("object with a blocked type: %s" % object["name"])

    def forbidden(self, flow: MISPHTTPFlow, message: str = "endpoint not allowed") -> None:
        ctx.log.error("request blocked: [%s]%s - %s" % (flow.request.method, flow.request.path, message))
        flow.response = http.Response.make(403, b"Forbidden", {"Content-Type": "text/plain"})

    def get_src_instance_id(self, flow: http.HTTPFlow) -> str:
        if flow.client_conn.peername[0] not in self.config["instances_host_mapping"]:
            raise ForbiddenException("source host does not exist in instances hosts mapping")

        return self.config["instances_host_mapping"][flow.client_conn.peername[0]]

    def get_dst_instance_id(self, flow: http.HTTPFlow) -> str:
        if flow.request.host not in self.config["instances_host_mapping"]:
            raise ForbiddenException("destination host does not exist in instances hosts mapping")

        return self.config["instances_host_mapping"][flow.request.host]

    @lru_cache
    def can_reach_compartment(self, flow: MISPHTTPFlow) -> bool:
        ctx.log.debug("compartment reach check - src: %s, dst: %s" % (flow.src_compartment_id, flow.dst_compartment_id))

        if flow.dst_compartment_id in self.config["compartments_rules"]["can_reach"][flow.src_compartment_id]:
            return True

        ctx.log.error("request blocked: [%s]%s - %s" %
                      (flow.request.method, flow.request.path, "cannot reach compartment"))
        return False

    @lru_cache
    def is_allowed_endpoint(self, method: str, path: str) -> bool:
        for endpoint in self.allowed_endpoints:
            if re.match(endpoint["regex"], path) and method in endpoint["methods"]:
                return True

        return False

    def get_event_from_message(self, message: http.Message) -> dict:
        if message.content is None:
            return Exception("empty message body")
        try:
            event = message.json()
            if "Event" not in event:
                raise Exception("no `Event` property in request body")
            return event
        except json.decoder.JSONDecodeError:
            raise Exception("invalid JSON body")

    def get_shadow_attributes_from_message(self, message: http.Message) -> dict:
        if message.content is None:
            return Exception("empty message body")
        try:
            return message.json()
        except json.decoder.JSONDecodeError:
            raise Exception("invalid JSON body")


addons = [MispGuard()]
