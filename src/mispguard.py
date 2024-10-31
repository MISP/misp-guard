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
import logging
import logging.config
import yaml

with open("logging.yaml", "r") as f:
    yaml_config = yaml.safe_load(f.read())
    logging.config.dictConfig(yaml_config)

logger = logging.getLogger(__name__)


class ForbiddenException(Exception):
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
    is_sighting: bool = False
    is_galaxy: bool = False
    is_analyst_data: bool = False
    is_analyst_data_index: bool = False
    is_analyst_note: bool = False
    is_analyst_opinion: bool = False
    is_analyst_relationship: bool = False


class MispGuard:
    def __init__(self):
        self.config: dict = {}
        self.allowed_endpoints = [
            {"regex": r"^\/servers\/getVersion$", "methods": ["GET"]},
            {"regex": r"^\/servers\/postTest$", "methods": ["POST"]},
            {"regex": r"^\/events\/index$", "methods": ["POST"]},
            {"regex": r"^\/events\/filterEventIdsForPush$", "methods": ["POST"]},
            {"regex": r"^\/events\/view\/[\w\-]{36}$", "methods": ["HEAD"]},
            {"regex": r"^\/events\/add.*$", "methods": ["POST"]},
            {"regex": r"^\/events\/edit\/[\w\-]{36}.*$", "methods": ["POST"]},
            {
                "regex": r"^\/servers\/getAvailableSyncFilteringRules$",
                "methods": ["GET"],
            },
            {"regex": r"^\/events\/view.*$", "methods": ["GET"]},
            {"regex": r"^\/shadow_attributes\/index.*$", "methods": ["GET"]},
            {"regex": r"^\/galaxies/pushCluster$", "methods": ["POST"]},
            {"regex": r"^\/galaxy_clusters\/restSearch$", "methods": ["POST"]},
            {"regex": r"^\/galaxy_clusters\/view\/[\w\-]{36}$", "methods": ["GET"]},
            {"regex": r"^\/sightings\/restSearch\/event$", "methods": ["POST"]},
            {
                "regex": r"^\/sightings\/bulkSaveSightings\/[\w\-]{36}$",
                "methods": ["POST"],
            },
            {"regex": r"^\/analyst_data\/indexMinimal$", "methods": ["POST"]},
            {
                "regex": r"^\/analyst_data\/index\/Note\/uuid\[\]\:[\w\-]{36}.json$",
                "methods": ["GET"],
            },
            {
                "regex": r"^\/analyst_data\/index\/Opinion\/uuid\[\]\:[\w\-]{36}.json$",
                "methods": ["GET"],
            },
            {
                "regex": r"^\/analyst_data\/index\/Relationship\/uuid\[\]\:[\w\-]{36}.json$",
                "methods": ["GET"],
            },
            {
                "regex": r"^\/analyst_data\/filterAnalystDataForPush$",
                "methods": ["POST"],
            },
            {
                "regex": r"^\/analyst_data\/pushAnalystData$",
                "methods": ["POST"],
            },
        ]

    def configure(self, updated):
        if ctx.options.config and exists(ctx.options.config):
            try:
                with open("config.schema.json", "r") as file:
                    schema = json.load(file)
                self.config = json.load(open(ctx.options.config))

                validate(
                    instance=self.config,
                    schema=schema,
                    format_checker=Draft202012Validator.FORMAT_CHECKER,
                )

            except Exception as e:
                logger.error("failed to load config file: %s" % str(e))
                exit(1)

        else:
            logger.error("failed to load config file, use: `--set config=config.json`")
            exit(1)
        logger.info("MispGuard initialized")

    def load(self, loader):
        loader.add_option("config", str, "", "MISP Guard configuration file")

    def request(self, flow: http.HTTPFlow) -> None:
        if not (self.url_is_allowed(flow) or self.domain_is_allowed(flow)):
            try:
                flow = self.enrich_flow(flow)
                if self.can_reach_compartment(flow) and self.is_allowed_endpoint(
                    flow.request.method, flow.request.path
                ):
                    return self.process_request(flow)
            except ForbiddenException as ex:
                logger.error(ex)
                return self.forbidden(flow, str(ex))
            except Exception as ex:
                logger.error(ex)
                return self.forbidden(flow, "unexpected error, rejecting request")

            # filter out requests to the allowed endpoints
            logger.error("rejecting non allowed request to %s" % flow.request.path)
            return self.forbidden(flow)
        else:
            try:
                if self.src_instance_is_allowed(flow):
                    logger.info(
                        "request from allowed url - skipping further processing"
                    )
            except ForbiddenException as ex:
                logger.error(ex)
                return self.forbidden(flow, str(ex))
            except Exception as ex:
                logger.error(ex)
                return self.forbidden(flow, "unexpected error, rejecting request")

    def response(self, flow: http.HTTPFlow) -> None:
        if not (self.url_is_allowed(flow) or self.domain_is_allowed(flow)):
            try:
                flow = self.enrich_flow(flow)
                if self.can_reach_compartment(flow):
                    return self.process_response(flow)
            except ForbiddenException as ex:
                logger.error(ex)
                return self.forbidden(flow, str(ex))
            except Exception as ex:
                logger.error(ex)
                return self.forbidden(flow, "unexpected error, rejecting response")
        else:
            try:
                if self.src_instance_is_allowed(flow):
                    logger.info(
                        "response from allowed url - skipping further processing"
                    )
            except ForbiddenException as ex:
                logger.error(ex)
                return self.forbidden(flow, str(ex))
            except Exception as ex:
                logger.error(ex)
                return self.forbidden(flow, "unexpected error, rejecting response")

    def url_is_allowed(self, flow: http.HTTPFlow) -> bool:
        if flow.request.url in self.config["allowlist"]["urls"]:
            return True
        else:
            return False

    def domain_is_allowed(self, flow: http.HTTPFlow) -> bool:
        if flow.request.host in self.config["allowlist"]["domains"]:
            return True
        else:
            return False

    def enrich_flow(self, flow: http.HTTPFlow) -> MISPHTTPFlow:
        logger.debug("enriching http flow")
        flow.__class__ = MISPHTTPFlow
        flow.src_instance_id = self.get_src_instance_id(flow)
        flow.dst_instance_id = self.get_dst_instance_id(flow)
        flow.src_compartment_id = self.config["instances"][flow.src_instance_id][
            "compartment_id"
        ]
        flow.dst_compartment_id = self.config["instances"][flow.dst_instance_id][
            "compartment_id"
        ]

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

        if "/galaxies/pushCluster" in flow.request.path:
            flow.is_push = True
            flow.is_galaxy = True

        if (
            "/galaxy_clusters/restSearch" in flow.request.path
            or "/galaxy_clusters/view" in flow.request.path
        ):
            flow.is_pull = True
            flow.is_galaxy = True

        if "/sightings/restSearch/event" in flow.request.path:
            flow.is_pull = True
            flow.is_sighting = True

        if "/analyst_data/indexMinimal" in flow.request.path:
            flow.is_pull = True
            flow.is_analyst_data = True

        if "/analyst_data/index/Note/" in flow.request.path:
            flow.is_pull = True
            flow.is_analyst_data = True
            flow.is_analyst_note = True

        if "/analyst_data/index/Opinion/" in flow.request.path:
            flow.is_pull = True
            flow.is_analyst_data = True
            flow.is_analyst_opinion = True

        if "/analyst_data/index/Relationship/" in flow.request.path:
            flow.is_pull = True
            flow.is_analyst_data = True
            flow.is_analyst_relationship = True

        if "/analyst_data/filterAnalystDataForPush" in flow.request.path:
            flow.is_push = True
            flow.is_analyst_data = True
            flow.is_analyst_data_index = True

        if "/analyst_data/pushAnalystData" in flow.request.path:
            flow.is_push = True
            flow.is_analyst_data = True

        return flow

    def process_request(self, flow: MISPHTTPFlow) -> None:
        logger.debug("processing request")
        logger.info(
            "received request - [%s]%s" % (flow.request.method, flow.request.path)
        )

        if flow.is_push and flow.is_event:
            try:
                event = self.get_event_from_message(flow.request)
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            # process block rules
            rules = self.get_rules(flow)
            return self.process_event(rules, event, flow)

        if flow.is_push and flow.is_event_index:
            params = flow.request.json()

            if (
                "minimal" not in params
                or params["minimal"] != 1
                or "published" not in params
                or params["published"] != 1
            ):
                raise ForbiddenException(
                    "{'minimal': 1, 'published': 1} is required for /events/index requests"
                )

        if flow.is_push and flow.is_galaxy:
            try:
                galaxy = flow.request.json()
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            rules = self.get_rules(flow)
            return self.process_galaxy_clusters(rules, galaxy, flow)

        if flow.is_pull and "/galaxy_clusters/restSearch" in flow.request.path:
            params = flow.request.json()
            if (
                "minimal" not in params
                or params["minimal"] != 1
                or "published" not in params
                or params["published"] != 1
            ):
                raise ForbiddenException(
                    "{'minimal': 1, 'published': 1} is required for /galaxy_clusters/restSearch requests"
                )

        if flow.is_push and flow.is_sighting:
            try:
                sightings = flow.request.json()
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            rules = self.get_rules(flow)
            return self.process_sightings(rules, sightings, flow)

        if flow.is_push and flow.is_analyst_data and not flow.is_analyst_data_index:
            try:
                analyst_data = flow.request.json()
                logger.debug(analyst_data)
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            rules = self.get_rules(flow)
            return self.process_analyst_data(rules, [analyst_data], flow)

    def process_response(self, flow: MISPHTTPFlow) -> None:
        logger.debug("processing response")
        if flow.is_pull and flow.is_event and flow.request.method == "HEAD":
            logger.debug("pull request [HEAD]/events/view passthrough")
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
                shadow_attributes_aux = self.get_shadow_attributes_from_message(
                    flow.response
                )
                for shadow_attribute in shadow_attributes_aux:
                    shadow_attributes.append(shadow_attribute["ShadowAttribute"])
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            rules = self.get_rules(flow)
            return self.process_shadow_attributes(rules, shadow_attributes, flow)

        if (
            flow.is_pull
            and flow.is_galaxy
            and "/galaxy_clusters/view" in flow.request.path
        ):
            try:
                galaxy_cluster = self.get_galaxy_cluster_from_message(flow.response)
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            rules = self.get_rules(flow)
            return self.process_galaxy_clusters(rules, [galaxy_cluster], flow)

        if flow.is_pull and flow.is_sighting:
            try:
                sightings = flow.response.json()
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            rules = self.get_rules(flow)
            return self.process_sightings(rules, sightings, flow)

        if flow.is_pull and flow.is_analyst_data:
            try:
                analyst_data = flow.response.json()
            except Exception as ex:
                return self.forbidden(flow, str(ex))

            rules = self.get_rules(flow)
            return self.process_analyst_data(rules, analyst_data, flow)

    def get_rules(self, flow: MISPHTTPFlow) -> list:
        logger.debug("getting misp-guard instance rules")
        rules = {}
        if flow.is_push:
            rules = self.config["instances"][flow.src_instance_id]
        if flow.is_pull:
            rules = self.config["instances"][flow.dst_instance_id]

        return rules

    def process_event(self, rules: dict, event: dict, flow: MISPHTTPFlow) -> None:
        logger.debug("processing outgoing event: %s" % event["Event"]["info"])

        try:
            self.check_event_level_rules(rules, event)
            self.check_attribute_level_rules(rules, event["Event"]["Attribute"])
            self.check_object_level_rules(rules, event["Event"]["Object"])

        except ForbiddenException as ex:
            return self.forbidden(flow, str(ex))

    def process_shadow_attributes(
        self, rules: dict, shadow_attributes: dict, flow: MISPHTTPFlow
    ) -> None:
        logger.debug("processing shadow attributes")

        try:
            self.check_attribute_level_rules(rules, shadow_attributes)
        except ForbiddenException as ex:
            return self.forbidden(flow, str(ex))

    def process_galaxy_clusters(
        self, rules: dict, galaxy_clusters: dict, flow: MISPHTTPFlow
    ) -> None:
        logger.debug("processing galaxy clusters")

        for galaxy_cluster in galaxy_clusters:
            try:
                self.check_blocked_galaxy_distribution_levels(
                    rules["blocked_distribution_levels"], galaxy_cluster
                )
            except ForbiddenException as ex:
                return self.forbidden(flow, str(ex))

    def process_sightings(
        self, rules: dict, sightings: dict, flow: MISPHTTPFlow
    ) -> None:
        logger.debug("processing sighting")

        try:
            # no rules for sightings yet
            return None
        except ForbiddenException as ex:
            return self.forbidden(flow, str(ex))

    def process_analyst_data(
        self, rules: dict, analyst_data: dict, flow: MISPHTTPFlow
    ) -> None:
        logger.debug("processing analyst data")

        for elem in analyst_data:
            try:
                if "Note" in elem:
                    self.check_analyst_data_rules(rules, elem["Note"])

                if "Opinion" in elem:
                    self.check_analyst_data_rules(rules, elem["Opinion"])

                if "Relationship" in elem:
                    self.check_analyst_relationship_rules(rules, elem["Relationship"])

                return None
            except ForbiddenException as ex:
                return self.forbidden(flow, str(ex))

    def check_event_level_rules(self, rules: dict, event: dict) -> None:
        logger.debug("checking event level rules")

        self.check_blocked_event_tags(rules["taxonomies_rules"], event)
        self.check_event_required_taxonomies(rules["taxonomies_rules"], event)
        self.check_blocked_event_distribution_levels(
            rules["blocked_distribution_levels"], event
        )
        self.check_blocked_event_sharing_groups_uuids(
            rules["blocked_sharing_groups_uuids"], event
        )

        if "Note" in event["Event"]:
            self.check_analyst_data_rules(rules, event["Event"]["Note"])

        if "Opinion" in event["Event"]:
            self.check_analyst_data_rules(rules, event["Event"]["Opinion"])

        if "Relationship" in event["Event"]:
            self.check_analyst_relationship_rules(rules, event["Event"]["Relationship"])

    def check_attribute_level_rules(self, rules: dict, attributes: dict) -> None:
        logger.debug("checking attribute level rules")
        for attribute in attributes:
            self.check_blocked_attribute_categories(
                rules["blocked_attribute_categories"], attribute
            )
            self.check_blocked_attribute_types(
                rules["blocked_attribute_types"], attribute
            )
            self.check_blocked_attribute_distribution_levels(
                rules["blocked_distribution_levels"], attribute
            )
            self.check_blocked_attribute_tags(rules["taxonomies_rules"], attribute)
            self.check_attribute_required_taxonomies(
                rules["taxonomies_rules"], attribute
            )
            self.check_blocked_attribute_sharing_groups_uuids(
                rules["blocked_sharing_groups_uuids"], attribute
            )

            if "ShadowAttribute" in attribute:
                self.check_attribute_level_rules(rules, attribute["ShadowAttribute"])

            if "Note" in attribute:
                self.check_analyst_data_rules(rules, attribute["Note"])

            if "Opinion" in attribute:
                self.check_analyst_data_rules(rules, attribute["Opinion"])

            if "Relationship" in attribute:
                self.check_analyst_relationship_rules(rules, attribute["Relationship"])

    def check_object_level_rules(self, rules: dict, objects: dict) -> None:
        for object in objects:
            self.check_blocked_object_distribution_levels(
                rules["blocked_distribution_levels"], object
            )
            self.check_blocked_object_sharing_groups_uuids(
                rules["blocked_sharing_groups_uuids"], object
            )
            self.check_blocked_object_types(rules["blocked_object_types"], object)
            self.check_attribute_level_rules(rules, object["Attribute"])

            if "Note" in object:
                self.check_analyst_data_rules(rules, object["Note"])

            if "Opinion" in object:
                self.check_analyst_data_rules(rules, object["Opinion"])

            if "Relationship" in object:
                self.check_analyst_relationship_rules(rules, object["Relationship"])

    def check_analyst_data_rules(self, rules: dict, analyst_data: dict) -> None:
        self.check_blocked_analyst_data_distribution_levels(
            rules["blocked_distribution_levels"], analyst_data
        )
        # TODO: MISP does not support have sharing group UUIDs for analyst data
        # self.check_blocked_analyst_data_sharing_groups_uuids(
        #     rules["blocked_sharing_groups_uuids"], analyst_data
        # )

    def check_analyst_relationship_rules(
        self, rules: dict, analyst_relationship: dict
    ) -> None:
        self.check_blocked_analyst_data_distribution_levels(
            rules["blocked_distribution_levels"], analyst_relationship
        )

        if analyst_relationship["related_object_type"] == "Event":
            self.check_event_level_rules(rules, analyst_relationship["related_object"])

        if analyst_relationship["related_object_type"] == "Object":
            self.check_object_level_rules(rules, [analyst_relationship["related_object"]["Object"]])

        if analyst_relationship["related_object_type"] == "Attribute":
            self.check_attribute_level_rules(
                rules, [analyst_relationship["related_object"]["Attribute"]]
            )

        if analyst_relationship["related_object_type"] == "GalaxyCluster":
            self.check_blocked_galaxy_distribution_levels(
                rules["blocked_distribution_levels"],
                analyst_relationship["related_object"],
            )

        if analyst_relationship["related_object_type"] == "Note":
            self.check_analyst_data_rules(rules, analyst_relationship["related_object"])

        if analyst_relationship["related_object_type"] == "Opinion":
            self.check_analyst_data_rules(rules, analyst_relationship["related_object"])

        if analyst_relationship["related_object_type"] == "Relationship":
            self.check_analyst_relationship_rules(
                rules, analyst_relationship["related_object"]
            )

        # TODO: MISP does not support have sharing group UUIDs for analyst data
        # self.check_blocked_analyst_data_sharing_groups_uuids(
        #     rules["blocked_sharing_groups_uuids"], analyst_relationship
        # )

    def check_event_required_taxonomies(
        self, taxonomies_rules: dict, event: dict
    ) -> None:
        logger.debug("checking required event taxonomies")

        if len(taxonomies_rules["required_taxonomies"]) == 0:
            return True

        if not "Tag" in event["Event"]:
            raise ForbiddenException("event is missing required taxonomies")

        for required_taxonomy in taxonomies_rules["required_taxonomies"]:
            logger.debug("checking required taxonomy: %s" % required_taxonomy)
            allowed_tags = taxonomies_rules["allowed_tags"].get(required_taxonomy, [])

            self.check_required_taxonomy_exists(
                required_taxonomy, event["Event"]["Tag"], allowed_tags
            )

        return True

    def check_attribute_required_taxonomies(
        self, taxonomies_rules: dict, attribute: dict
    ) -> None:
        logger.debug("checking required attribute taxonomies")
        if len(taxonomies_rules["required_taxonomies"]) == 0:
            return True

        if not "Tag" in attribute:
            raise ForbiddenException("attribute is missing required taxonomies")

        for required_taxonomy in taxonomies_rules["required_taxonomies"]:
            logger.debug("checking required taxonomy: %s" % required_taxonomy)
            allowed_tags = taxonomies_rules["allowed_tags"].get(required_taxonomy, [])

            self.check_required_taxonomy_exists(
                required_taxonomy, attribute["Tag"], allowed_tags
            )

        return True

    def check_required_taxonomy_exists(
        self, required_taxonomy: str, tags: list, allowed_tags: list = []
    ) -> bool:
        for tag in tags:
            if tag["name"].startswith(required_taxonomy + ":"):
                # if there are allowed tags, check if the tag is allowed
                # otherwise any tag of this taxonomy is ok
                if len(allowed_tags) == 0 or tag["name"] in allowed_tags:
                    return True

        raise ForbiddenException(
            "event is missing required taxonomy: %s" % required_taxonomy
        )

    def check_blocked_event_tags(self, taxonomies_rules: dict, event: dict) -> None:
        if "Tag" in event["Event"]:
            for tag in event["Event"]["Tag"]:
                if tag["name"] in taxonomies_rules["blocked_tags"]:
                    raise ForbiddenException("event has blocked tag: %s" % tag["name"])

    def check_blocked_event_distribution_levels(
        self, blocked_distribution_levels: list, event: dict
    ) -> None:
        if event["Event"]["distribution"] in blocked_distribution_levels:
            raise ForbiddenException(
                "event has blocked distribution level: %s"
                % event["Event"]["distribution"]
            )

    def check_blocked_event_sharing_groups_uuids(
        self, blocked_sharing_groups_uuids: list, event: dict
    ) -> None:
        if blocked_sharing_groups_uuids and "SharingGroup" in event["Event"]:
            if event["Event"]["SharingGroup"]["uuid"] in blocked_sharing_groups_uuids:
                raise ForbiddenException(
                    "event has blocked sharing group uuid: %s"
                    % event["Event"]["SharingGroup"]["uuid"]
                )

    def check_blocked_attribute_tags(
        self, taxonomies_rules: dict, attribute: dict
    ) -> None:
        if taxonomies_rules["blocked_tags"] and "Tag" in attribute:
            for tag in attribute["Tag"]:
                if tag["name"] in taxonomies_rules["blocked_tags"]:
                    raise ForbiddenException(
                        "attribute with a blocked tag: %s" % tag["name"]
                    )

    def check_blocked_attribute_distribution_levels(
        self, blocked_distribution_levels: list, attribute: dict
    ) -> None:
        if (
            "distribution" in attribute
            and attribute["distribution"] in blocked_distribution_levels
        ):
            raise ForbiddenException(
                "attribute with a blocked distribution level: %s"
                % attribute["distribution"]
            )

    def check_blocked_attribute_sharing_groups_uuids(
        self, blocked_sharing_groups_uuids: list, attribute: dict
    ) -> None:
        if "SharingGroup" in attribute:
            if attribute["SharingGroup"]["uuid"] in blocked_sharing_groups_uuids:
                raise ForbiddenException(
                    "attribute with a blocked sharing group uuid: %s"
                    % attribute["SharingGroup"]["uuid"]
                )

    def check_blocked_attribute_types(
        self, blocked_attribute_types: list, attribute: dict
    ) -> None:
        if attribute["type"] in blocked_attribute_types:
            raise ForbiddenException(
                "attribute with a blocked type: %s" % attribute["type"]
            )

    def check_blocked_attribute_categories(
        self, blocked_attribute_categories: list, attribute: dict
    ) -> None:
        if attribute["category"] in blocked_attribute_categories:
            raise ForbiddenException(
                "attribute with a blocked category: %s" % attribute["category"]
            )

    def check_blocked_object_distribution_levels(
        self, blocked_distribution_levels: list, object: dict
    ) -> None:
        if object["distribution"] in blocked_distribution_levels:
            raise ForbiddenException(
                "object with a blocked distribution level: %s" % object["distribution"]
            )

    def check_blocked_object_sharing_groups_uuids(
        self, blocked_sharing_groups_uuids: list, object: dict
    ) -> None:
        if "SharingGroup" in object:
            if object["SharingGroup"]["uuid"] in blocked_sharing_groups_uuids:
                raise ForbiddenException(
                    "object with a blocked sharing group uuid: %s"
                    % object["SharingGroup"]["uuid"]
                )

    def check_blocked_object_types(
        self, blocked_object_types: list, object: dict
    ) -> None:
        if object["name"] in blocked_object_types:
            raise ForbiddenException("object with a blocked type: %s" % object["name"])

    def check_blocked_galaxy_distribution_levels(
        self, blocked_distribution_levels: list, galaxy_cluster: dict
    ) -> None:
        if (
            galaxy_cluster["GalaxyCluster"]["distribution"]
            in blocked_distribution_levels
        ):
            raise ForbiddenException(
                "galaxy cluster has blocked distribution level: %s"
                % galaxy_cluster["GalaxyCluster"]["distribution"]
            )

    def check_blocked_analyst_data_distribution_levels(
        self, blocked_distribution_levels: list, analyst_data: dict
    ) -> None:
        if analyst_data["distribution"] in blocked_distribution_levels:
            raise ForbiddenException(
                "analyst data has blocked distribution level: %s"
                % analyst_data["distribution"]
            )

    def check_blocked_analyst_data_sharing_groups_uuids(
        self, blocked_sharing_groups_uuids: list, analyst_data: dict
    ) -> None:
        if analyst_data["SharingGroup"]["uuid"] in blocked_sharing_groups_uuids:
            raise ForbiddenException(
                "analyst data has blocked sharing group uuid: %s"
                % analyst_data["SharingGroup"]["uuid"]
            )

    def forbidden(
        self, flow: MISPHTTPFlow, message: str = "endpoint not allowed"
    ) -> None:
        logger.error(
            "request blocked: [%s]%s - %s"
            % (flow.request.method, flow.request.path, message)
        )
        flow.response = http.Response.make(
            403, b"Forbidden", {"Content-Type": "text/plain"}
        )

    def get_src_instance_id(self, flow: http.HTTPFlow) -> str:
        if flow.client_conn.peername[0] not in self.config["instances_host_mapping"]:
            raise ForbiddenException(
                "source host %s does not exist in instances hosts mapping"
                % flow.client_conn.peername[0]
            )

        return self.config["instances_host_mapping"][flow.client_conn.peername[0]]

    def src_instance_is_allowed(self, flow: http.HTTPFlow) -> bool:
        if flow.client_conn.peername[0] not in self.config["instances_host_mapping"]:
            raise ForbiddenException(
                "source host %s does not exist in instances hosts mapping"
                % flow.client_conn.peername[0]
            )

        return True

    def get_dst_instance_id(self, flow: http.HTTPFlow) -> str:
        if flow.request.host not in self.config["instances_host_mapping"]:
            raise ForbiddenException(
                "destination host %s does not exist in instances hosts mapping"
                % flow.request.host
            )

        return self.config["instances_host_mapping"][flow.request.host]

    @lru_cache
    def can_reach_compartment(self, flow: MISPHTTPFlow) -> bool:
        logger.debug(
            "compartment reach check - src: %s, dst: %s"
            % (flow.src_compartment_id, flow.dst_compartment_id)
        )

        if (
            flow.dst_compartment_id
            in self.config["compartments_rules"]["can_reach"][flow.src_compartment_id]
        ):
            return True

        logger.error(
            "request blocked: [%s]%s - %s"
            % (flow.request.method, flow.request.path, "cannot reach compartment")
        )
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

    def get_galaxy_cluster_from_message(self, message: http.Message) -> dict:
        if message.content is None:
            return Exception("empty message body")
        try:
            return message.json()
        except json.decoder.JSONDecodeError:
            raise Exception("invalid JSON body")


addons = [MispGuard()]
