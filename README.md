# misp-guard
`misp-guard` is a [mitmproxy](https://mitmproxy.org/) addon designed to apply configurable filters that prevent the unintentional leakage of sensitive threat intelligence data while facilitating controlled information sharing.

`misp-guard` functions as a proxy specifically designed to interact with and understand the MISP synchronization protocol. It monitors communications between MISP instances, allowing for real-time inspection and enforcement of security policies. MISP Guard effectively blocks incoming or outgoing data that matches configured filtering rules, ensuring sensitive or restricted information is not unintentionally shared.

> **NOTE: By default this addon will block all outgoing HTTP requests that are not required during a MISP server sync. However, individual URLs or domains can be allowed if necessary.**

## Objectives
To prevent data leakage in high-security environments such as military networks or critical infrastructure systems, `misp-guard` plays a crucial role by acting as a configurable enforcement layer during MISP instance synchronization. Its fine-grained filtering capabilities allow organizations to maintain strict control over what information is shared, ensuring compliance with compartmentalization policies and mitigating the risk of accidental data exposure.

Supported filters include:  
- **Compartment Rules**: Restrict data sharing based on predefined compartmentalization policies.  
- **Taxonomy Rules**: Control synchronization by enforcing taxonomy-specific filtering.  
- **Blocked Distribution Levels**: Prevent data with specific distribution levels from being shared.  
- **Blocked Sharing Groups**: Exclude data linked to restricted sharing groups.  
- **Blocked Attribute Types**: Filter specific attribute types from synchronization.  
- **Blocked Attribute Categories**: Restrict data belonging to selected attribute categories.  
- **Blocked Object Types**: Prohibit synchronization of specific object types.  
- **URL Allowlists**: Permit only explicitly approved URLs to pass through.  

## PUSH
```mermaid
sequenceDiagram
    participant MISP A 
    participant MISP Guard
    participant MISP B

    rect rgb(191, 223, 255)
    note right of MISP A: PUSH Events 

    MISP B->>MISP Guard: [GET]/servers/getVersion
    MISP Guard->>MISP A: [GET]/servers/getVersion
    MISP A->>MISP Guard: [GET]/servers/getVersion
    MISP Guard->>MISP B: [GET]/servers/getVersion
    
    MISP B->>MISP Guard: [HEAD]/events/view/[UUID]
    note right of MISP Guard: Only `minimal` search requests to /events/index are allowed
    MISP Guard->>MISP A: [HEAD]/events/view/[UUID]
    MISP A->>MISP Guard: [HEAD]/events/view/[UUID]
    MISP Guard->>MISP B: [HEAD]/events/view/[UUID]
    
    rect rgb(191, 223, 255)
    note left of MISP Guard: 404: If the event does not exists in MISP A
    MISP B->>+MISP Guard: [POST]/events/add
    note right of MISP Guard: Outgoing Event is inspected and rejected with 403 if any block rule matches
    MISP Guard->>-MISP A: [POST]/events/add
    MISP A->>MISP Guard: [POST]/events/add
    MISP Guard->>MISP B: [POST]/events/add
    end

    rect rgb(191, 223, 255)
    note left of MISP Guard: 200: If the event already exists in MISP A
    MISP B->>+MISP Guard: [POST]/events/edit/[UUID]
    note right of MISP Guard: Outgoing Event is inspected and rejected with 403 if any block rule matches
    MISP Guard->>-MISP A: [POST]/events/edit/[UUID]
    MISP A->>MISP Guard: [POST]/events/edit/[UUID]
    MISP Guard->>MISP B: [POST]/events/edit/[UUID]
    end
    end 

    rect rgb(191, 223, 255)
    note right of MISP A: PUSH GalaxyClusters
    MISP B->>+MISP Guard: [POST]/galaxies/pushCluster
    note right of MISP Guard: Outgoing Galaxy Cluster is inspected and rejected with 403 if any block rule matches
    MISP Guard->>-MISP A: [POST]/galaxies/pushCluster
    MISP A->>MISP Guard: [POST]/galaxies/pushCluster
    MISP Guard->>MISP B: [POST]/galaxies/pushCluster
    end

    rect rgb(191, 223, 255)
    note right of MISP A: PUSH Sightings
    MISP B->>+MISP Guard: [POST]/sightings/bulkSaveSightings/[UUID]
    note right of MISP Guard: Outgoing Sightings are inspected and rejected with 403 if any block rule matches
    MISP Guard->>-MISP A: [POST]/sightings/bulkSaveSightings/[UUID]
    MISP A->>MISP Guard: [POST]/sightings/bulkSaveSightings/[UUID]
    MISP Guard->>MISP B: [POST]/sightings/bulkSaveSightings/[UUID]
    end
    
    rect rgb(191, 223, 255)
    note right of MISP A: PUSH AnalystData
    MISP B->>+MISP Guard: [POST]/analyst_data/filterAnalystDataForPush
    MISP A->>MISP Guard: [POST]/analyst_data/filterAnalystDataForPush
    MISP Guard->>MISP B: [POST]/analyst_data/filterAnalystDataForPush

    MISP B->>+MISP Guard: [POST]/analyst_data/pushAnalystData
    note right of MISP Guard: Outgoing Analyst Data is inspected and rejected with 403 if any block rule matches
    MISP Guard->>-MISP A: [POST]/analyst_data/pushAnalystData
    MISP A->>MISP Guard: [POST]/analyst_data/pushAnalystData
    MISP Guard->>MISP B: [POST]/analyst_data/pushAnalystData
    end
```

## PULL
```mermaid
sequenceDiagram
    participant MISP A
    participant MISP Guard
    participant MISP B

    rect rgb(191, 223, 255)
    note right of MISP A: PULL Events 
    MISP A->>MISP Guard: [GET]/servers/getVersion
    MISP Guard->>MISP B: [GET]/servers/getVersion
    MISP B->>MISP Guard: [GET]/servers/getVersion
    MISP Guard->>MISP A: [GET]/servers/getVersion

    MISP A->>+MISP Guard: [POST]/events/index
    note right of MISP Guard: Only `minimal` search requests to /events/index are allowed
    MISP Guard->>-MISP B: [POST]/events/index
    MISP B->>MISP Guard: [POST]/events/index
    MISP Guard->>MISP A: [POST]/events/index

    MISP A->>MISP Guard: [GET]/events/view/[UUID]
    MISP Guard->>MISP B: [GET]/events/view/[UUID]
    MISP B->>+MISP Guard: [GET]/events/view/[UUID]
    note right of MISP Guard: Incoming Event is inspected and rejected with 403 if any block rule matches
    MISP Guard->>-MISP A: [GET]/events/view/[UUID]

    MISP A->>MISP Guard: [GET]/users/view/me.json
    MISP Guard->>MISP B: [GET]/users/view/me.json
    MISP B->>MISP Guard: [GET]/users/view/me.json
    MISP Guard->>MISP A: [GET]/users/view/me.json
    end

    rect rgb(191, 223, 255)
    note right of MISP A: PULL ShadowAttributes 
    MISP A->>MISP Guard: [GET]/shadow_attributes/index
    MISP Guard->>MISP B: [GET]/shadow_attributes/index
    MISP B->>+MISP Guard: [GET]/shadow_attributes/index
    note right of MISP Guard: Incoming Shadow Attributes are inspected and rejected with 403 if any block rule matches
    MISP Guard->>-MISP A: [GET]/shadow_attributes/index
    end

    rect rgb(191, 223, 255)
    note right of MISP A: GalaxyClusters 
    MISP A->>+MISP Guard: [POST]/galaxy_clusters/restSearch
    note right of MISP Guard: Only `minimal` search requests to /galaxy_clusters/restSearch are allowed
    MISP Guard->>-MISP B: [POST]/galaxy_clusters/restSearch
    MISP B->>MISP Guard: [POST]/galaxy_clusters/restSearch
    MISP Guard->>MISP A: [POST]/galaxy_clusters/restSearch

    MISP A->>MISP Guard: [GET]/galaxy_clusters/view/[UUID]
    MISP Guard->>MISP B: [GET]/galaxy_clusters/view/[UUID]
    MISP B->>+MISP Guard: [GET]/galaxy_clusters/view/[UUID]
    note right of MISP Guard: Incoming Galaxy Cluster is inspected and rejected with 403 if any block rule matches
    MISP Guard->>-MISP A: [GET]/galaxy_clusters/view/[UUID]

    MISP A->>MISP Guard: [GET]/users/view/me.json
    MISP Guard->>MISP B: [GET]/users/view/me.json
    MISP B->>MISP Guard: [GET]/users/view/me.json
    MISP Guard->>MISP A: [GET]/users/view/me.json
    end

    rect rgb(191, 223, 255)
    note right of MISP A: PULL Sightings 
    MISP A->>MISP Guard: [POST]/sightings/restSearch/event
    MISP Guard->>MISP B: [POST]/sightings/restSearch/event
    MISP B->>+MISP Guard: [POST]/sightings/restSearch/event
    note right of MISP Guard: Incoming Sightings are inspected and rejected with 403 if any block rule matches
    MISP Guard->>-MISP A: [POST]/sightings/restSearch/event
    end
    
    rect rgb(191, 223, 255)
    note right of MISP A: PULL AnalystData 
    MISP A->>MISP Guard: [POST]/analyst_data/indexMinimal
    MISP Guard->>MISP B: [POST]/analyst_data/indexMinimal
    MISP B->>+MISP Guard: [POST]/analyst_data/indexMinimal
    MISP Guard->>-MISP A: [POST]/analyst_data/indexMinimal

    MISP A->>MISP Guard: [GET]/analyst_data/index/[Note|Opinion|Relationship]/uuid:[UUID].json
    MISP Guard->>MISP B: [GET]/analyst_data/index/[Note|Opinion|Relationship]/uuid:[UUID].json
    MISP B->>+MISP Guard: [GET]/analyst_data/index/[Note|Opinion|Relationship]/uuid:[UUID].json
    note right of MISP Guard: Incoming Analyst Data is inspected and rejected with 403 if any block rule matches
    MISP Guard->>-MISP A: [GET]/analyst_data/index/[Note|Opinion|Relationship]/uuid:[UUID].json

    MISP A->>MISP Guard: [GET]/users/view/me.json
    MISP Guard->>MISP B: [GET]/users/view/me.json
    MISP B->>MISP Guard: [GET]/users/view/me.json
    MISP Guard->>MISP A: [GET]/users/view/me.json
    end
```




> **NOTE: The `MISP A` server needs to have the `misp-guard` hostname configured as the server hostname you are going to pull from, **not** the `MISP B` hostname.**

**Supported block rules:**
* `compartments_rules`: Compartments can be interpreted as a VLAN where one or more MISP are living, each compartment defines to which other compartments allows to sync.
* `taxonomies_rules`:
  * `required_taxonomies`: Taxonomies that have to be present in a event, otherwise it will be blocked.
  * `allowed_tags`: For each of the `required_taxonomies` a subset of allowed tags can be specified.
  * `blocked_tags`: Tags that cannot be present in any of the event entities.
* `blocked_distribution_levels`: Blocks if the event/objects/attributes matches one of the blocked distribution levels.
  * `"0"`: Organisation Only
  * `"1"`: Community Only
  * `"2"`: Connected Communities
  * `"3"`: All Communities
  * `"4"`: Sharing Group
  * `"5"`: Inherit Event
* `blocked_sharing_groups_uuids`: Blocks if the event/objects/attributes matches one of the blocked sharing groups uuids.
* `blocked_attribute_types`: Blocks if the event contains an attribute matching one of this types.
* `blocked_attribute_categories`: Blocks if the event contains an attribute matching one of this categories.
* `blocked_object_types`: Blocks if the event contains an object matching one of this types.

**Allowlist**

* To allow individual URLs or domains, simply add them as a JSON array under the `allowlist` element.
  * `urls` The entire URL is checked and only exact calls are allowed.
  * `domains` In contrast, only the domain is checked and any website behind the domain can be queried. Should only be used if adding exact URLs is not possible.

See sample config [here](src/test/test_config.json).

## Instructions

### Requirements
* Python 3.12 or newer.
* `venv` (recommended).

### Installation
```bash
$ git clone https://github.com/MISP/misp-guard.git
$ cd src/
$ apt install python3.12-venv
$ python3.12 -m venv .venv
$ source .venv/bin/activate
$ pip3 install -r requirements.txt
```

### Setup

1. Define your block rules in the `config.json` file.
2. Start mitmproxy with the `mispguard` addon:
    ```
    $ mitmdump -s mispguard.py -p 8888 --certs *=cert.pem --set config=config.json
    Loading script mispguard.py
    MispGuard initialized
    Proxy server listening at *:8888
    ``` 
    _Add `-k` to accept self-signed certificates._

3. Configure the proxy in your MISP instance, set the following MISP  `Proxy.host` and `Proxy.port` settings accordingly.

Done, outgoing MISP sync requests will be inspected and dropped according to the specified block rules.


> NOTE: add `-v` to `mitmdump` to increase verbosity and display debug logs.

### Testing
 ```
 $ pip install pytest pytest-asyncio
 $ src src/
 $ pytest
 ```
