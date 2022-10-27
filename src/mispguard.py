"""
This script filters out MISP events based on a set of rules.
The rules are defined in a JSON file.
"""

from faulthandler import is_enabled
from functools import lru_cache
from mitmproxy import http, ctx
import json
import re
from os.path import exists
from enum import Enum


class ForbiddenException (Exception):
    pass


class MispHTTPFlow(http.HTTPFlow):
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
                self.config = json.load(open(ctx.options.config))
            except Exception as e:
                ctx.log.error("failed to load config file: %s" % str(e))
                exit(1)

            if self.config["block_rules"]:
                ctx.log.info("running block rules: %s" % ','.join([rule["id"] for rule in self.config["block_rules"]]))
        else:
            ctx.log.error("failed to load config file, use: `--set config=config.json`")
            exit(1)
        ctx.log.info("MispGuard initialized")

    def load(self, loader):
        loader.add_option("config", str, "", "MISP Guard configuration file")

    def request(self, flow: http.HTTPFlow) -> None:
        flow = self.enrich_flow(flow)
        try:
            if self.can_reach_compartment(flow) and self.is_allowed_endpoint(flow.request.method, flow.request.path):
                return self.process_request(flow)
        except Exception as ex:
            ctx.log.error(ex)
            return self.forbidden(flow, "unexpected error, rejecting request")

        # filter out requests to the allowed endpoints
        ctx.log.error("rejecting non allowed request to %s" % flow.request.path)
        return self.forbidden(flow)

    def response(self,  flow: http.HTTPFlow) -> None:
        flow = self.enrich_flow(flow)
        try:
            if self.can_reach_compartment(flow):
                return self.process_response(flow)
        except Exception as ex:
            ctx.log.error(ex)
            return self.forbidden(flow, "unexpected error, rejecting response")

    def enrich_flow(self, flow: http.HTTPFlow) -> MispHTTPFlow:
        ctx.log.debug("enriching http flow")
        flow.__class__ = MispHTTPFlow
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

    def process_request(self, flow: MispHTTPFlow) -> None:
        ctx.log.debug("processing request")
        ctx.log.info("received request - [%s]%s" % (flow.request.method, flow.request.path))

        if flow.is_event and flow.is_push:
            try:
                event = self.get_event_from_message(flow.request)
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            # process block rules
            return self.process_event(event, flow)

        if flow.is_event_index:
            params = flow.request.json()

            if "minimal" not in params or params["minimal"] != 1 or "published" not in params or params["published"] != 1:
                raise ForbiddenException(
                    "{'minimal': 1, 'published': 1} is required for /events/index requests")

    def process_response(self, flow: MispHTTPFlow) -> None:
        ctx.log.debug("processing response")
        if flow.is_pull and flow.is_event and flow.request.method == "HEAD":
            return None  # passthrough

        if flow.is_pull and flow.is_event and flow.request.method != "POST":
            if flow.request.content is None:
                return self.forbidden(flow, "empty request body")

            try:
                event = self.get_event_from_message(flow.response)
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            return self.process_event(event, flow)

        if flow.is_pull and flow.is_shadow_attributes:
            try:
                shadow_attributes = []
                shadow_attributes_aux = self.get_shadow_attributes_from_message(flow.response)
                for shadow_attribute in shadow_attributes_aux:
                    shadow_attributes.append(shadow_attribute["ShadowAttribute"])
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            return self.process_shadow_attributes(shadow_attributes, flow)

    def process_event(self, event: dict, flow: MispHTTPFlow) -> None:
        ctx.log.debug("processing outgoing event: %s" % event["Event"]["info"])

        try:
            self.check_event_level_rules(flow, event)
            self.check_attribute_level_rules(flow, event["Event"]["Attribute"])
            self.check_object_level_rules(flow, event["Event"]["Object"])

        except ForbiddenException as ex:
            return self.forbidden(flow, str(ex))

    def process_shadow_attributes(self, shadow_attributes: dict, flow: MispHTTPFlow) -> None:
        ctx.log.debug("processing shadow attributes")

        try:
            self.check_attribute_level_rules(flow, shadow_attributes)
        except ForbiddenException as ex:
            return self.forbidden(flow, str(ex))

    def check_event_level_rules(self, flow: MispHTTPFlow, event: dict) -> None:
        ctx.log.debug("checking event level rules")
        self.check_event_required_taxonomies(flow, event)
        for rule in self.config["block_rules"]:
            self.check_blocked_event_distribution_levels(rule, event)
            self.check_blocked_event_sharing_groups_uuids(rule, event)
            self.check_blocked_event_tags(rule, event)

    def check_attribute_level_rules(self, flow: MispHTTPFlow, attributes: dict) -> None:
        ctx.log.debug("checking attribute level rules")
        for attribute in attributes:
            self.check_attribute_required_taxonomies(flow, attribute)
            for rule in self.config["block_rules"]:
                self.check_blocked_attribute_distribution_levels(rule, attribute)
                self.check_blocked_attribute_sharing_groups_uuids(rule, attribute)
                self.check_blocked_attribute_types(rule, attribute)
                self.check_blocked_attribute_categories(rule, attribute)
                self.check_blocked_attribute_tags(rule, attribute)
            if "ShadowAttribute" in attribute:
                self.check_attribute_level_rules(flow, attribute["ShadowAttribute"])

    def check_object_level_rules(self, flow: MispHTTPFlow, objects: dict) -> None:
        for object in objects:
            for rule in self.config["block_rules"]:
                self.check_blocked_object_distribution_levels(rule, object)
                self.check_blocked_object_sharing_groups_uuids(rule, object)
                self.check_blocked_object_types(rule, object)

            self.check_attribute_level_rules(flow, object["Attribute"])

    def check_event_required_taxonomies(self, flow: MispHTTPFlow, event: dict) -> None:
        ctx.log.debug("checking required event taxonomies")
        if flow.is_push:
            taxonomies_rules = self.config["instances"][flow.src_instance_id]["taxonomies_rules"]
        if flow.is_pull:
            taxonomies_rules = self.config["instances"][flow.dst_instance_id]["taxonomies_rules"]

        if len(taxonomies_rules["required_taxonomies"]) == 0:
            return True

        if not "Tag" in event["Event"]:
            raise ForbiddenException("event is missing required taxonomies")

        for required_taxonomy in taxonomies_rules["required_taxonomies"]:
            ctx.log.debug("checking required taxonomy: %s" % required_taxonomy)
            allowed_tags = taxonomies_rules["allowed_tags"].get(required_taxonomy, [])
            blocked_tags = taxonomies_rules["blocked_tags"].get(required_taxonomy, [])

            self.check_required_taxonomy_exists(required_taxonomy, event["Event"]["Tag"], allowed_tags, blocked_tags)

        return True

    def check_required_taxonomy_exists(self, required_taxonomy: str, tags: list, allowed_tags: list = [], blocked_tags: list = []) -> bool:
        for tag in tags:
            if tag["name"] in blocked_tags:
                raise ForbiddenException("tag %s is blocked" % tag["name"])

            if tag["name"].startswith(required_taxonomy + ":"):
                # if there are allowed tags, check if the tag is allowed
                # otherwise any tag of this taxonomy is ok
                if len(allowed_tags) == 0 or tag["name"] in allowed_tags:
                    return True

        raise ForbiddenException("event is missing required taxonomy: %s" % required_taxonomy)

    def check_attribute_required_taxonomies(self, flow: MispHTTPFlow, attribute: dict) -> None:
        ctx.log.debug("checking required atribute taxonomies")
        # TODO
        pass

    def check_blocked_event_tags(self, rule: dict, event: dict) -> None:
        if rule["blocked_tags"] and "Tag" in event["Event"]:
            for tag in event["Event"]["Tag"]:
                if tag["name"] in rule["blocked_tags"]:
                    raise ForbiddenException("event has blocked tag: %s. blocked by rule: %s" %
                                             (tag["name"], rule["id"]))

    def check_blocked_event_distribution_levels(self, rule: dict, event: dict) -> None:
        if event["Event"]["distribution"] in rule["blocked_distribution_levels"]:
            raise ForbiddenException("event has blocked distribution level: %s. blocked by rule: %s" %
                                     (event["Event"]["distribution"], rule["id"]))

    def check_blocked_event_sharing_groups_uuids(self, rule: dict, event: dict) -> None:
        if rule["blocked_sharing_groups_uuids"] and "SharingGroup" in event["Event"]:
            if event["Event"]["SharingGroup"]["uuid"] in rule["blocked_sharing_groups_uuids"]:
                raise ForbiddenException("event has blocked sharing group uuid: %s. blocked by rule: %s" %
                                         (event["Event"]["SharingGroup"]["uuid"], rule["id"]))

    def check_blocked_attribute_tags(self, rule: dict, attribute: dict) -> None:
        if rule["blocked_tags"] and "Tag" in attribute:
            for tag in attribute["Tag"]:
                if tag["name"] in rule["blocked_tags"]:
                    raise ForbiddenException("attribute with a blocked tag: %s. blocked by rule: %s" %
                                             (tag["name"], rule["id"]))

    def check_blocked_attribute_distribution_levels(self, rule: dict, attribute: dict) -> None:
        if "distribution" in attribute and attribute["distribution"] in rule["blocked_distribution_levels"]:
            raise ForbiddenException("attribute with a blocked distribution level: %s. blocked by rule: %s" %
                                     (attribute["distribution"], rule["id"]))

    def check_blocked_attribute_sharing_groups_uuids(self, rule: dict, attribute: dict) -> None:
        if rule["blocked_sharing_groups_uuids"] and "SharingGroup" in attribute:
            if attribute["SharingGroup"]["uuid"] in rule["blocked_sharing_groups_uuids"]:
                raise ForbiddenException("attribute with a blocked sharing group uuid: %s. blocked by rule: %s" %
                                         (attribute["SharingGroup"]["uuid"], rule["id"]))

    def check_blocked_attribute_types(self, rule: dict, attribute: dict) -> None:
        if attribute["type"] in rule["blocked_attribute_types"]:
            raise ForbiddenException("attribute with a blocked type: %s. blocked by rule: %s" %
                                     (attribute["type"], rule["id"]))

    def check_blocked_attribute_categories(self, rule: dict, attribute: dict) -> None:
        if attribute["category"] in rule["blocked_attribute_categories"]:
            raise ForbiddenException("attribute with a blocked category: %s. blocked by rule: %s" %
                                     (attribute["category"], rule["id"]))

    def check_blocked_object_attribute_tags(self, rule: dict, object: dict) -> None:
        for attribute in object["Attribute"]:
            self.check_blocked_attribute_tags(rule, attribute)

    def check_blocked_object_distribution_levels(self, rule: dict, object: dict) -> None:
        if object["distribution"] in rule["blocked_distribution_levels"]:
            raise ForbiddenException("object with a blocked distribution level: %s. blocked by rule: %s" %
                                     (object["distribution"], rule["id"]))

    def check_blocked_object_sharing_groups_uuids(self, rule: dict, object: dict) -> None:
        if rule["blocked_sharing_groups_uuids"] and "SharingGroup" in object:
            if object["SharingGroup"]["uuid"] in rule["blocked_sharing_groups_uuids"]:
                raise ForbiddenException("object with a blocked sharing group uuid: %s. blocked by rule: %s" %
                                         (object["SharingGroup"]["uuid"], rule["id"]))

    def check_blocked_object_types(self, rule: dict, object: dict) -> None:
        if object["name"] in rule["blocked_object_types"]:
            raise ForbiddenException("object with a blocked type: %s. blocked by rule: %s" %
                                     (object["name"], rule["id"]))

    def forbidden(self, flow: MispHTTPFlow, message: str = "endpoint not allowed") -> None:
        ctx.log.error("request blocked: [%s]%s - %s" % (flow.request.method, flow.request.path, message))
        flow.response = http.Response.make(403, b"Forbidden", {"Content-Type": "text/plain"})

    def get_src_instance_id(self, flow: http.HTTPFlow) -> str:
        if flow.client_conn.peername[0] not in self.config["instances_host_mapping"]:
            raise ForbiddenException("Source host does not exist in compartments mapping")

        return self.config["instances_host_mapping"][flow.client_conn.peername[0]]

    def get_dst_instance_id(self, flow: http.HTTPFlow) -> str:
        if flow.request.host not in self.config["instances_host_mapping"]:
            raise ForbiddenException("Source host does not exist in compartments mapping")

        return self.config["instances_host_mapping"][flow.request.host]

    @lru_cache
    def can_reach_compartment(self, flow: MispHTTPFlow) -> bool:
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
