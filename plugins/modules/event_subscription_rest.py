#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: event_subscription_rest
short_description: Resource module for Event Subscription Rest
description:
- Manage operations create and update of the resource Event Subscription Rest.
- Create Rest/Webhook Subscription Endpoint for list of registered events.
- Update Rest/Webhook Subscription Endpoint for list of registered events.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Event Subscription Rest's payload.
    suboptions:
      description:
        description: Description.
        type: str
      filter:
        description: Event Subscription Rest's filter.
        suboptions:
          eventIds:
            description: Event Ids (Comma separated event ids).
            elements: str
            type: list
        type: dict
      name:
        description: Name.
        type: str
      subscriptionEndpoints:
        description: Event Subscription Rest's subscriptionEndpoints.
        suboptions:
          instanceId:
            description: (From Get Rest/Webhook Subscription Details --> pick instanceId).
            type: str
          subscriptionDetails:
            description: Event Subscription Rest's subscriptionDetails.
            suboptions:
              connectorType:
                description: Connector Type (Must be REST).
                type: str
            type: dict
        type: list
      subscriptionId:
        description: Subscription Id (Unique UUID).
        type: str
      version:
        description: Version.
        type: str
    type: list
requirements:
- dnacentersdk >= 2.4.0
- python >= 3.5
seealso:
# Reference to SDK documentation of current version
- name: SDK function create_rest_webhook_event_subscription used
  link: >
    https://dnacentersdk.rtfd.io/en/latest/api/api.html#dnacentersdk.api.v2_2_3_3.
    event_management.EventManagement.create_rest_webhook_event_subscription

- name: SDK function update_rest_webhook_event_subscription used
  link: >
    https://dnacentersdk.rtfd.io/en/latest/api/api.html#dnacentersdk.api.v2_2_3_3.
    event_management.EventManagement.update_rest_webhook_event_subscription

notes:
  - Paths used are post /dna/intent/api/v1/event/subscription/rest,
    put /dna/intent/api/v1/event/subscription/rest
"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.event_subscription_rest:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:

- name: Update all
  cisco.dnac.event_subscription_rest:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "statusUri": "string"
    }
"""
