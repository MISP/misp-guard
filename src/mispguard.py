"""
This script filters out MISP events based on a set of rules.
The rules are defined in a JSON file.
"""

from functools import lru_cache
from mitmproxy import http, ctx, connection
from mitmproxy.proxy import server_hooks
from jsonschema import validate, Draft202012Validator
import json
import re
from os.path import exists, abspath, dirname
import logging
import logging.config
import yaml
import re

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

with open("logging.yaml", "r") as f:
    yaml_config = yaml.safe_load(f.read())
    logging.config.dictConfig(yaml_config)


def sanitize_log_input(s: str) -> str:
    return re.sub(r"[\r\n\t\x00-\x1f\x7f]", "", s)


class SafeFormatter(logging.Formatter):
    def format(self, record):
        if record.args:
            record.args = tuple(sanitize_log_input(str(arg)) for arg in record.args)
        record.msg = sanitize_log_input(str(record.msg))
        return super().format(record)


for handler in logging.root.handlers:
    if isinstance(handler.formatter, logging.Formatter):
        old_format = handler.formatter._fmt
        handler.setFormatter(SafeFormatter(fmt=old_format))

logger = logging.getLogger(__name__)


class ForbiddenException(Exception):
    pass


class ConfigWatcher(FileSystemEventHandler):
    def __init__(self, addon):
        self.addon = addon

    def on_modified(self, event):
        if ctx.options.config in event.src_path:
            # check if the config file was modified
            if self.addon.config_checksum != hash(open(ctx.options.config).read()):
                logger.info(f"{ctx.options.config} modified, reloading addon...")
                self.addon.configure(True)


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
    is_analyst_data_minimal_index: bool = False
    is_analyst_note: bool = False
    is_analyst_opinion: bool = False
    is_analyst_relationship: bool = False


class MispGuard:
    def __init__(self):
        # watchdog observer setup for config file changes
        self.config_watcher = ConfigWatcher(self)
        self.observer = Observer()
        self.observer.schedule(self.config_watcher, ".", recursive=False)
        self.observer.start()

        self.config: dict = {}
        self.config_checksum = None
        self.allowed_endpoints = [
            {"regex": r"^\/servers\/getVersion$", "methods": ["GET"]},
            {"regex": r"^\/servers\/postTest$", "methods": ["POST"]},
            {"regex": r"^\/users\/view\/me\.json$", "methods": ["GET"]},
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
                self.config_checksum = hash(open(ctx.options.config).read())

                validate(
                    instance=self.config,
                    schema=schema,
                    format_checker=Draft202012Validator.FORMAT_CHECKER,
                )

                # create instances_host_mapping dictionary
                self.config["instances_host_mapping"] = {}
                for instance_id, instance in self.config["instances"].items():
                    self.config["instances_host_mapping"][
                        instance["host"]
                    ] = instance_id
                    self.config["instances_host_mapping"][instance["ip"]] = instance_id

            except Exception as e:
                logger.error("failed to load config file: %s" % str(e))
                exit(1)

            logger.info("configuration loaded")
            logger.info(json.dumps(self.config, indent=4))

        else:
            logger.error("failed to load config file, use: `--set config=config.json`")
            exit(1)
        logger.info("MispGuard initialized")

    def load(self, loader):
        loader.add_option("config", str, "", "MISP Guard configuration file")

    def server_connect(self, data: server_hooks.ServerConnectionHookData):
        dst_host, dst_port = data.server.address

        if dst_host in self.config["allowlist"]["domains"]:
            logger.error(f"domain {dst_host} was allowed by the allowlist")
            return None

        if dst_host in self.config["instances_host_mapping"]:
            dst_instance_id = self.config["instances_host_mapping"][dst_host]

            if dst_port == self.config["instances"][dst_instance_id]["port"]:
                return None
            else:
                logger.error(
                    f"destination port {dst_port} for host {dst_host} is not allowed"
                )

        data.server.error = "connection not allowed."

    def request(self, flow: http.HTTPFlow) -> None:
        if not (self.url_is_allowed(flow) or self.domain_is_allowed(flow)):
            try:
                flow = self.enrich_flow(flow)
                if (
                    self.can_reach_compartment(flow)
                    and self.can_reach_dst_host_port(flow)
                    and self.is_allowed_endpoint(flow.request.method, flow.request.path)
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
                if self.can_reach_compartment(flow) and self.can_reach_dst_host_port(
                    flow
                ):
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
            logger.info(f"url {flow.request.url} was allowed by the allowlist")
            return True
        else:
            return False

    def domain_is_allowed(self, flow: http.HTTPFlow) -> bool:
        if flow.request.host in self.config["allowlist"]["domains"]:
            logger.info(f"domain {flow.request.host} was allowed by the allowlist")
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
            flow.is_analyst_data_minimal_index = True

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
            flow.is_analyst_data_minimal_index = True

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

        if (
            flow.is_push
            and flow.is_analyst_data
            and not flow.is_analyst_data_minimal_index
        ):
            try:
                analyst_data = flow.request.json()
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

            # check flow has a header with the user org UUID
            # `Security.user_org_uuid_in_response_header` setting in MISP
            if flow.response.headers.get("X-UserOrgUUID") is not None:
                logger.debug("Checking the X-UserOrgUUID header in the response")
                rules["X-UserOrgUUID"] = flow.response.headers.get("X-UserOrgUUID")

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

        if (
            flow.is_pull
            and flow.is_analyst_data
            and not flow.is_analyst_data_minimal_index
        ):
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
        self.check_blocked_event_report_rules(rules, event)

        self.check_event_sharing_groups_rules(rules, event)

        if "Note" in event["Event"]:
            for note in event["Event"]["Note"]:
                self.check_analyst_data_rules(rules, note)

        if "Opinion" in event["Event"]:
            for opinion in event["Event"]["Opinion"]:
                self.check_analyst_data_rules(rules, opinion)

        if "Relationship" in event["Event"]:
            for relationship in event["Event"]["Relationship"]:
                self.check_analyst_relationship_rules(rules, relationship)

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
            self.check_attribute_sharing_groups_rules(rules, attribute)

            if "ShadowAttribute" in attribute:
                self.check_attribute_level_rules(rules, attribute["ShadowAttribute"])

            if "Note" in attribute:
                for note in attribute["Note"]:
                    self.check_analyst_data_rules(rules, note)

            if "Opinion" in attribute:
                for opinion in attribute["Opinion"]:
                    self.check_analyst_data_rules(rules, opinion)

            if "Relationship" in attribute:
                for relationship in attribute["Relationship"]:
                    self.check_analyst_relationship_rules(rules, relationship)

    def check_object_level_rules(self, rules: dict, objects: dict) -> None:
        for object in objects:
            self.check_blocked_object_distribution_levels(
                rules["blocked_distribution_levels"], object
            )

            self.check_object_sharing_groups_rules(rules, object)
            self.check_blocked_object_types(rules["blocked_object_types"], object)
            self.check_attribute_level_rules(rules, object["Attribute"])

            if "Note" in object:
                for note in object["Note"]:
                    self.check_analyst_data_rules(rules, note)

            if "Opinion" in object:
                for opinion in object["Opinion"]:
                    self.check_analyst_data_rules(rules, opinion)

            if "Relationship" in object:
                for relationship in object["Relationship"]:
                    self.check_analyst_relationship_rules(rules, relationship)

    def check_analyst_data_rules(self, rules: dict, analyst_data: dict) -> None:
        self.check_blocked_analyst_data_distribution_levels(
            rules["blocked_distribution_levels"], analyst_data
        )
        # TODO: MISP does not support sharing group UUIDs for analyst data
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
            self.check_object_level_rules(
                rules, [analyst_relationship["related_object"]["Object"]]
            )

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
                if len(allowed_tags) == 0 or tag["name"].lower() in [
                    allowed_tag.lower() for allowed_tag in allowed_tags
                ]:
                    return True

        raise ForbiddenException(
            "event is missing required taxonomy: %s" % required_taxonomy
        )

    def check_blocked_event_tags(self, taxonomies_rules: dict, event: dict) -> None:
        if "Tag" in event["Event"]:
            for tag in event["Event"]["Tag"]:
                if tag["name"].lower() in [
                    blocked_tag.lower()
                    for blocked_tag in taxonomies_rules["blocked_tags"]
                ]:
                    raise ForbiddenException("event has blocked tag: %s" % tag["name"])

    def check_blocked_event_distribution_levels(
        self, blocked_distribution_levels: list, event: dict
    ) -> None:
        if str(event["Event"]["distribution"]) in blocked_distribution_levels:
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

    def check_blocked_event_report_distribution_levels(
        self, blocked_distribution_levels: list, report: dict
    ) -> None:
        if str(report["distribution"]) in blocked_distribution_levels:
            raise ForbiddenException(
                "event report has blocked distribution level: %s"
                % report["distribution"]
            )

    def check_blocked_event_report_rules(self, rules: dict, event: dict) -> None:
        if "EventReport" in event["Event"]:
            for report in event["Event"]["EventReport"]:
                self.check_blocked_event_report_distribution_levels(
                    rules["blocked_distribution_levels"], report
                )

                # TODO: MISP does not support sharing group UUIDs for event reports
                # self.check_blocked_event_report_sharing_groups_uuids(
                #     rules["blocked_sharing_groups_uuids"], report
                # )

    def check_blocked_attribute_tags(
        self, taxonomies_rules: dict, attribute: dict
    ) -> None:
        if taxonomies_rules["blocked_tags"] and "Tag" in attribute:
            for tag in attribute["Tag"]:
                if tag["name"].lower() in [
                    blocked_tag.lower()
                    for blocked_tag in taxonomies_rules["blocked_tags"]
                ]:
                    raise ForbiddenException(
                        "attribute with a blocked tag: %s" % tag["name"]
                    )

    def check_blocked_attribute_distribution_levels(
        self, blocked_distribution_levels: list, attribute: dict
    ) -> None:
        if (
            "distribution" in attribute
            and str(attribute["distribution"]) in blocked_distribution_levels
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
        if str(object["distribution"]) in blocked_distribution_levels:
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

    def check_sharing_group_user_org_uuid(self, user_org_uuid: str, elem: dict) -> None:
        for sharing_group_org in elem["SharingGroup"]["SharingGroupOrg"]:
            if sharing_group_org["Organisation"]["uuid"] == user_org_uuid:
                return None

        for sharing_group_server in elem["SharingGroup"]["SharingGroupServer"]:
            if sharing_group_server["all_orgs"]:
                logger.warning(
                    "sharing group server with `all_orgs` flag found, skip X-UserOrgUUID check"
                )
                return None

        raise ForbiddenException(
            "user with organisation uuid: %s (X-UserOrgUUID) not in sharing group"
            % user_org_uuid
        )

    def check_event_sharing_groups_rules(self, rules: dict, event: dict) -> None:
        self.check_blocked_event_sharing_groups_uuids(
            rules["blocked_sharing_groups_uuids"], event
        )
        if "X-UserOrgUUID" in rules and "SharingGroup" in event["Event"]:
            self.check_sharing_group_user_org_uuid(
                rules["X-UserOrgUUID"], event["Event"]
            )

    def check_object_sharing_groups_rules(self, rules: dict, object: dict) -> None:
        self.check_blocked_object_sharing_groups_uuids(
            rules["blocked_sharing_groups_uuids"], object
        )
        if "X-UserOrgUUID" in rules and "SharingGroup" in object:
            self.check_sharing_group_user_org_uuid(rules["X-UserOrgUUID"], object)

    def check_attribute_sharing_groups_rules(
        self, rules: dict, attribute: dict
    ) -> None:
        self.check_blocked_attribute_sharing_groups_uuids(
            rules["blocked_sharing_groups_uuids"], attribute
        )
        if "X-UserOrgUUID" in rules and "SharingGroup" in attribute:
            self.check_sharing_group_user_org_uuid(rules["X-UserOrgUUID"], attribute)

    def check_blocked_object_types(
        self, blocked_object_types: list, object: dict
    ) -> None:
        if object["name"].lower() in [
            blocked_object_type.lower() for blocked_object_type in blocked_object_types
        ]:
            raise ForbiddenException("object with a blocked type: %s" % object["name"])

    def check_blocked_galaxy_distribution_levels(
        self, blocked_distribution_levels: list, galaxy_cluster: dict
    ) -> None:
        if (
            str(galaxy_cluster["GalaxyCluster"]["distribution"])
            in blocked_distribution_levels
        ):
            raise ForbiddenException(
                "galaxy cluster has blocked distribution level: %s"
                % galaxy_cluster["GalaxyCluster"]["distribution"]
            )

    def check_blocked_analyst_data_distribution_levels(
        self, blocked_distribution_levels: list, analyst_data: dict
    ) -> None:
        if str(analyst_data["distribution"]) in blocked_distribution_levels:
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
    def can_reach_dst_host_port(self, flow: MISPHTTPFlow) -> bool:
        logger.debug(
            "host reach check - src: %s, dst: %s:%d"
            % (flow.src_instance_id, flow.dst_instance_id, flow.request.port)
        )

        if flow.request.port == self.config["instances"][flow.dst_instance_id]["port"]:
            return True

        logger.error(
            "request blocked: [%s]%s - %s"
            % (
                flow.request.method,
                flow.request.path,
                "destination port is not allowed",
            )
        )
        return False

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
            raise Exception("empty message body")
        try:
            event = message.json()
            if "Event" not in event:
                raise Exception("no `Event` property in request body")
            return event
        except json.decoder.JSONDecodeError:
            raise Exception("invalid JSON body")

    def get_shadow_attributes_from_message(self, message: http.Message) -> dict:
        if message.content is None:
            raise Exception("empty message body")
        try:
            return message.json()
        except json.decoder.JSONDecodeError:
            raise Exception("invalid JSON body")

    def get_galaxy_cluster_from_message(self, message: http.Message) -> dict:
        if message.content is None:
            raise Exception("empty message body")
        try:
            return message.json()
        except json.decoder.JSONDecodeError:
            raise Exception("invalid JSON body")


addons = [MispGuard()]
