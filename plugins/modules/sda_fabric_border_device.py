#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabric_border_device
short_description: Resource module for Sda Fabric Border Device
description:
- Manage operations create and delete of the resource Sda Fabric Border Device.
- Add border device in SDA Fabric.
- Delete border device from SDA Fabric.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deviceManagementIpAddress:
    description: DeviceManagementIpAddress query parameter.
    type: str
  payload:
    version_added: "6.0.0"
    description: Sda Fabric Border Device's payload.
    suboptions:
      borderSessionType:
        description: Border Session Type.
        type: str
      connectedToInternet:
        description: Connected to Internet.
        type: bool
      deviceManagementIpAddress:
        description: Management Ip Address of the Device which is provisioned successfully.
        type: str
      externalConnectivityIpPoolName:
        description: External Connectivity IpPool Name.
        type: str
      externalConnectivitySettings:
        description: Sda Fabric Border Device's externalConnectivitySettings.
        suboptions:
          externalAutonomouSystemNumber:
            description: External Autonomous System Number peer (e.g.,1-65535).
            type: str
          interfaceName:
            description: Interface Name.
            type: str
          l3Handoff:
            description: Sda Fabric Border Device's l3Handoff.
            suboptions:
              virtualNetwork:
                description: Sda Fabric Border Device's virtualNetwork.
                suboptions:
                  virtualNetworkName:
                    description: Virtual Network Name, that is associated to Fabric
                      Site.
                    type: str
                  vlanId:
                    description: Vlan Id (e.g.,2-4096 except for reserved VLANs (1002-1005,
                      2046, 4095)).
                    type: str
                type: dict
            type: list
        type: list
      externalDomainRoutingProtocolName:
        description: External Domain Routing Protocol Name.
        type: str
      internalAutonomouSystemNumber:
        description: Internal Autonomouns System Number (e.g.,1-65535).
        type: str
      siteNameHierarchy:
        description: Site Name Hierarchy of provisioned Device(site should be part of
          Fabric Site).
        type: str
    type: list
requirements:
- dnacentersdk == 2.4.5
- python >= 3.5
notes:
  - SDK Method used are
    sda.Sda.adds_border_device,
    sda.Sda.deletes_border_device,

  - Paths used are
    post /dna/intent/api/v1/business/sda/border-device,
    delete /dna/intent/api/v1/business/sda/border-device,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.sda_fabric_border_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
    - borderSessionType: string
      connectedToInternet: true
      deviceManagementIpAddress: string
      externalConnectivityIpPoolName: string
      externalConnectivitySettings:
      - externalAutonomouSystemNumber: string
        interfaceName: string
        l3Handoff:
        - virtualNetwork:
            virtualNetworkName: string
            vlanId: string
      externalDomainRoutingProtocolName: string
      internalAutonomouSystemNumber: string
      siteNameHierarchy: string

- name: Delete all
  cisco.dnac.sda_fabric_border_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    deviceManagementIpAddress: string

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "status": "string",
      "description": "string",
      "taskId": "string",
      "taskStatusUrl": "string",
      "executionStatusUrl": "string",
      "executionId": "string"
    }
"""
