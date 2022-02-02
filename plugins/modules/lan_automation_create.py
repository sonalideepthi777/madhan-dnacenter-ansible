#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: lan_automation_create
short_description: Resource module for Lan Automation Create
description:
- Manage operation create of the resource Lan Automation Create.
- Invoke this API to start LAN Automation for the given site.
version_added: '6.0.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Lan Automation Create's payload.
    suboptions:
      discoveredDeviceSiteNameHierarchy:
        description: Discovered device site name.
        type: str
      hostNameFileId:
        description: By using /dna/intent/api/v1/file/namespace/nw_orch api get the
          file id for the already uploaded file for the nw_orch namespace.
        type: str
      hostNamePrefix:
        description: Host name prefix which shall be assigned to the discovered device.
        type: str
      ipPools:
        description: Lan Automation Create's ipPools.
        suboptions:
          ipPoolName:
            description: Name of the IP pool.
            type: str
          ipPoolRole:
            description: Role of the IP pool.
            type: str
        type: list
      isisDomainPwd:
        description: Isis domain password in plain text.
        type: str
      mulitcastEnabled:
        description: To enable underlay native multicast.
        type: bool
      peerDeviceManagmentIPAddress:
        description: Peer seed device management IP address.
        type: str
      primaryDeviceInterfaceNames:
        description: The list of interfaces on primary seed device via which the discovered
          devices are connected.
        elements: str
        type: list
      primaryDeviceManagmentIPAddress:
        description: Primary seed device management IP address.
        type: str
    type: list
requirements:
- dnacentersdk == 2.4.5
- python >= 3.5
notes:
  - SDK Method used are
    lan_automation.LanAutomation.lan_automation_start,

  - Paths used are
    post /dna/intent/api/v1/lan-automation,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.lan_automation_create:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    payload:
    - discoveredDeviceSiteNameHierarchy: string
      hostNameFileId: string
      hostNamePrefix: string
      ipPools:
      - ipPoolName: string
        ipPoolRole: string
      isisDomainPwd: string
      mulitcastEnabled: true
      peerDeviceManagmentIPAddress: string
      primaryDeviceInterfaceNames:
      - string
      primaryDeviceManagmentIPAddress: string

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "errorCode": "string",
        "message": "string",
        "detail": "string"
      },
      "version": "string"
    }
"""
