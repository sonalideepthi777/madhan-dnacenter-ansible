#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = r"""
---
module: buildings_planned_access_points_info
short_description: Information module for Buildings Planned Access Points Info
description:
- This module represents an alias of the module buildings_planned_access_points_v1_info
version_added: '6.0.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  buildingId:
    description:
    - BuildingId path parameter. The instance UUID of the building hierarchy element.
    type: str
  limit:
    description:
    - Limit query parameter. The page size limit for the response, e.g. Limit=100 will return a maximum of 100 records.
    type: float
  offset:
    description:
    - >
      Offset query parameter. The page offset for the response. E.g. If limit=100, offset=0 will return first 100
      records, offset=1 will return next 100 records, etc.
    type: float
  radios:
    description:
    - Radios query parameter. Whether to include the planned radio details of the planned access points.
    type: bool
requirements:
- dnacentersdk >= 2.4.9
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Devices GetPlannedAccessPointsForBuildingV1
  description: Complete reference of the GetPlannedAccessPointsForBuildingV1 API.
  link: https://developer.cisco.com/docs/dna-center/#!get-planned-access-points-for-building
notes:
  - SDK Method used are
    devices.Devices.get_planned_access_points_for_building_v1,

  - Paths used are
    get /dna/intent/api/v1/buildings/{buildingId}/planned-access-points,
  - It should be noted that this module is an alias of buildings_planned_access_points_v1_info

"""

EXAMPLES = r"""
- name: Get all Buildings Planned Access Points Info
  cisco.dnac.buildings_planned_access_points_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    limit: 0
    offset: 0
    radios: True
    buildingId: string
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
          "attributes": {
            "id": 0,
            "instanceUuid": "string",
            "name": "string",
            "typeString": "string",
            "domain": "string",
            "heirarchyName": "string",
            "source": "string",
            "createDate": 0,
            "macAddress": "string"
          },
          "location": {
            "altitude": 0,
            "lattitude": 0,
            "longtitude": 0
          },
          "position": {
            "x": 0,
            "y": 0,
            "z": 0
          },
          "radioCount": 0,
          "radios": [
            {
              "attributes": {
                "id": 0,
                "instanceUuid": "string",
                "slotId": 0,
                "ifTypeString": "string",
                "ifTypeSubband": "string",
                "channel": 0,
                "channelString": "string",
                "ifMode": "string",
                "txPowerLevel": 0
              },
              "antenna": {
                "name": "string",
                "type": "string",
                "mode": "string",
                "azimuthAngle": 0,
                "elevationAngle": 0,
                "gain": 0
              },
              "isSensor": true
            }
          ],
          "isSensor": true
        }
      ],
      "version": 0,
      "total": 0
    }
"""
