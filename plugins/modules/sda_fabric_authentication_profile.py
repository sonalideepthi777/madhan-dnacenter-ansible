#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabric_authentication_profile
short_description: Resource module for Sda Fabric Authentication Profile
description:
- Manage operations create, update and delete of the resource Sda Fabric Authentication Profile.
- Add default authentication template in SDA Fabric.
- Delete default authentication profile in SDA Fabric.
- Update default authentication profile in SDA Fabric.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    version_added: "6.0.0"
    description: Sda Fabric Authentication Profile's payload.
    suboptions:
      authenticateTemplateName:
        description: Authenticate Template Name.
        type: str
      siteNameHierarchy:
        description: Path of sda Fabric Site.
        type: str
    type: list
  siteNameHierarchy:
    description: SiteNameHierarchy query parameter.
    type: str
requirements:
- dnacentersdk == 2.4.5
- python >= 3.5
notes:
  - SDK Method used are
    sda.Sda.add_default_authentication_profile,
    sda.Sda.delete_default_authentication_profile,
    sda.Sda.update_default_authentication_profile,

  - Paths used are
    post /dna/intent/api/v1/business/sda/authentication-profile,
    delete /dna/intent/api/v1/business/sda/authentication-profile,
    put /dna/intent/api/v1/business/sda/authentication-profile,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.sda_fabric_authentication_profile:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
    - authenticateTemplateName: string
      siteNameHierarchy: string

- name: Update all
  cisco.dnac.sda_fabric_authentication_profile:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
    - authenticateTemplateName: string
      authenticationOrder: string
      dot1xToMabFallbackTimeout: string
      numberOfHosts: string
      siteNameHierarchy: string
      wakeOnLan: true

- name: Delete all
  cisco.dnac.sda_fabric_authentication_profile:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    siteNameHierarchy: string

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
