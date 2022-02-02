#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: lan_automation_log_info
short_description: Information module for Lan Automation Log
description:
- Get all Lan Automation Log.
- Get Lan Automation Log by id.
- Invoke this API to get the  LAN Automation session logs based on the given Lan Automation session Id.
- Invoke this API to get the LAN Automation session logs.
version_added: '6.0.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  offset:
    description:
    - Offset query parameter. Offset/starting row of the LAN Automation session from which logs are required.
    type: str
  limit:
    description:
    - Limit query parameter. Number of LAN Automations sessions to be retrieved.
    type: str
  id:
    description:
    - Id path parameter. LAN Automation Session Identifier.
    type: str
requirements:
- dnacentersdk == 2.4.5
- python >= 3.5
notes:
  - SDK Method used are
    lan_automation.LanAutomation.lan_automation_log,
    lan_automation.LanAutomation.lan_automation_log_by_id,

  - Paths used are
    get /dna/intent/api/v1/lan-automation/log,
    get /dna/intent/api/v1/lan-automation/log/{id},

"""

EXAMPLES = r"""
- name: Get all Lan Automation Log
  cisco.dnac.lan_automation_log_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers:
      custom: value
    offset: string
    limit: string
  register: result

- name: Get Lan Automation Log by id
  cisco.dnac.lan_automation_log_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers:
      custom: value
    id: string
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        {
          "nwOrchId": "string",
          "entry": [
            {
              "logLevel": "string",
              "timeStamp": "string",
              "record": "string",
              "deviceId": "string"
            }
          ]
        }
      ],
      "version": "string"
    }
"""
