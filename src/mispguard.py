"""
This script filters out MISP events based on a set of rules.
The rules are defined in a JSON file.
"""

from mitmproxy import http, ctx
import json
import re
from os.path import exists


class ForbiddenException (Exception):
    pass


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
        try:
            for endpoint in self.allowed_endpoints:
                if re.match(endpoint["regex"], flow.request.path):
                    if flow.request.method in endpoint["methods"]:
                        if(self.is_external_request(flow)):
                            return self.process_external_request(flow)
                        else:
                            return self.process_internal_request(flow)
        except Exception as ex:
            ctx.log.error(ex)
            return self.forbidden(flow, "unexpected error, rejecting request")

        # filter out requests to the allowed endpoints
        ctx.log.error("rejecting non allowed request to %s" % flow.request.path)
        return self.forbidden(flow)

    def process_internal_request(self, flow: http.HTTPFlow) -> None:
        ctx.log.info("received internal request - [%s]%s" % (flow.request.method, flow.request.path))
        if "/events/add" in flow.request.path or "/events/edit" in flow.request.path:
            try:
                event = self.get_event_from_message(flow.request)
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            # process block rules
            return self.process_outgoing_event(event, flow)

    def process_external_request(self, flow: http.HTTPFlow) -> None:
        ctx.log.info("received external request - [%s]%s" % (flow.request.method, flow.request.path))

        if "/events/index" in flow.request.path:
            params = flow.request.json()

            if "minimal" not in params or params["minimal"] != 1 or "published" not in params or params["published"] != 1:
                raise ForbiddenException(
                    "{'minimal': 1, 'published': 1} is required for /events/index external requests")

        # redirect to internal server
        flow.request.host = self.config["misp"]["host"]
        flow.request.port = self.config["misp"]["port"]
        flow.request.scheme = "https"

    def process_outgoing_event(self, event: dict, flow: http.HTTPFlow) -> None:
        ctx.log.debug("processing outgoing event: %s" % event["Event"]["info"])

        try:
            self.check_event_level_rules(event)
            self.check_attribute_level_rules(event["Event"]["Attribute"])
            self.check_object_level_rules(event["Event"]["Object"])

        except ForbiddenException as ex:
            return self.forbidden(flow, str(ex))

    def process_outgoing_shadow_attributes(self, shadow_attributes: dict, flow: http.HTTPFlow) -> None:
        ctx.log.debug("processing outgoing shadow attributes...")

        # TODO: if only one shadow attribute is blocked, the whole request is blocked,
        # should we remove only the blocked one from the response?
        # this could lead to orphan attributes if the attribute was not pulled from the remote instance
        try:
            self.check_attribute_level_rules(shadow_attributes)
        except ForbiddenException as ex:
            return self.forbidden(flow, str(ex))

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            if(self.is_external_request(flow)):
                self.process_external_response(flow)
            else:
                self.process_internal_response(flow)
        except Exception as ex:
            ctx.log.error(ex)
            return self.forbidden(flow, "unexpected error, rejecting response")

    def process_external_response(self, flow: http.HTTPFlow) -> None:
        ctx.log.info("received external response - [%s]%s" % (flow.request.method, flow.request.path))

    def process_internal_response(self, flow: http.HTTPFlow) -> None:
        ctx.log.info("received internal response - [%s]%s" % (flow.request.method, flow.request.path))
        if "/events/view" in flow.request.path and flow.request.method == "HEAD":
            return None  # passthrough

        if "/events/view" in flow.request.path and flow.request.method != "POST":
            if flow.request.content is None:
                return self.forbidden(flow, "empty request body")

            try:
                event = self.get_event_from_message(flow.response)
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            return self.process_outgoing_event(event, flow)

        if "/shadow_attributes/index" in flow.request.path:
            try:
                shadow_attributes = []
                shadow_attributes_aux = self.get_shadow_attributes_from_message(flow.response)
                for shadow_attribute in shadow_attributes_aux:
                    shadow_attributes.append(shadow_attribute["ShadowAttribute"])
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            return self.process_outgoing_shadow_attributes(shadow_attributes, flow)

    def check_event_level_rules(self, event: dict) -> None:
        for rule in self.config["block_rules"]:
            self.check_blocked_event_distribution_levels(rule, event)
            self.check_blocked_event_sharing_groups_uuids(rule, event)
            self.check_blocked_event_tags(rule, event)

    def check_attribute_level_rules(self, attributes: dict) -> None:
        for attribute in attributes:
            for rule in self.config["block_rules"]:
                self.check_blocked_attribute_distribution_levels(rule, attribute)
                self.check_blocked_attribute_sharing_groups_uuids(rule, attribute)
                self.check_blocked_attribute_types(rule, attribute)
                self.check_blocked_attribute_categories(rule, attribute)
                self.check_blocked_attribute_tags(rule, attribute)
            if "ShadowAttribute" in attribute:
                self.check_attribute_level_rules(attribute["ShadowAttribute"])

    def check_object_level_rules(self, objects: dict) -> None:
        for object in objects:
            for rule in self.config["block_rules"]:
                self.check_blocked_object_distribution_levels(rule, object)
                self.check_blocked_object_sharing_groups_uuids(rule, object)
                self.check_blocked_object_types(rule, object)

            self.check_attribute_level_rules(object["Attribute"])

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

    def forbidden(self, flow: http.HTTPFlow, message: str = "endpoint not allowed") -> None:
        ctx.log.error("request blocked: [%s]%s - %s" % (flow.request.method, flow.request.path, message))
        flow.response = http.Response.make(403, b"Forbidden", {"Content-Type": "text/plain"})

    def is_external_request(self, flow: http.HTTPFlow) -> bool:
        ctx.log.debug("received request - [%s]%s" % (flow.request.method, flow.request.path))
        return flow.request.host == self.config["proxy"]["host"] and flow.request.port == self.config["proxy"]["port"]

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
