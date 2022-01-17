#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: reports_executions_info
short_description: Information module for Reports Executions
description:
- Get all Reports Executions.
- Get Reports Executions by id.
- Get details of all executions for a given report.
- Returns report content. Save the response to a file by converting the response data as a blob and setting the file format available from content-disposition response header.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  reportId:
    description:
    - ReportId path parameter. ReportId of report.
    type: str
  executionId:
    description:
    - ExecutionId path parameter. ExecutionId of report execution.
    type: str
  dirPath:
    description:
    - Directory absolute path. Defaults to the current working directory.
    type: str
  saveFile:
    description:
    - Enable or disable automatic file creation of raw response.
    type: bool
requirements:
- dnacentersdk >= 2.4.0
- python >= 3.5
seealso:
# Reference to SDK documentation of current version
- name: SDK function get_all_execution_details_for_a_given_report used
  link: >
    https://dnacentersdk.rtfd.io/en/latest/api/api.html#dnacentersdk.api.v2_2_3_3.
    reports.Reports.get_all_execution_details_for_a_given_report

- name: SDK function download_report_content used
  link: >
    https://dnacentersdk.rtfd.io/en/latest/api/api.html#dnacentersdk.api.v2_2_3_3.
    reports.Reports.download_report_content

notes:
  - Paths used are get /dna/intent/api/v1/data/reports/{reportId}/executions,
    get /dna/intent/api/v1/data/reports/{reportId}/executions/{executionId}
"""

EXAMPLES = r"""
- name: Get all Reports Executions
  cisco.dnac.reports_executions_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers:
      custom: value
    reportId: string
  register: result

- name: Get Reports Executions by id
  cisco.dnac.reports_executions_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers:
      custom: value
    reportId: string
    executionId: string
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: str
  sample: >
    "'string'"
"""
