#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from dnacentersdk import api
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
    dnac_compare_equality
)
from ansible_collections.cisco.dnac.plugins.module_utils.pydentic_validation import *
from ansible.module_utils.basic import AnsibleModule

import pandas as pd

__metaclass__ = type
__author__ = ("A Mohamed Rafeek, Natarajan")

DOCUMENTATION = r"""
---
module: accesspoint_workflow_manager
short_description: accesspoint_workflow_manager used to automate bulk AP configuration changes.
description:
- We can change the AP display name, AP name or Other Param based on the input.yml file
- Using by this package we can filter specific device details like family = Switches and Hubs
- We can compare input details with current AP configuration.
- Desired configuration will be updated to the needed APs Only
- Also able to reboot the Accesspoint if needed.
version_added: '6.7.0'
extends_documentation_fragment:
  - accesspoint_workflow_manager
author: A Mohamed Rafeek (@mohamedrafeek)
        Natarajan (@natarajan)

accesspoints:
    macAddress: It is string MAC address format
      managementIpAddress: String IP address format
      accesspointradiotype: It is number and should be 1,2,3 and 6
        1 - Will be 2.4 Ghz
        2 - Will be 5 Ghz
        3 - Will be XOR
        6 - Will be 6 Ghz
      apName: It should be String

requirements:
- dnacentersdk >= 2.4.5
- python >= 3.10
notes:
  - dnacsdk Method used 
"""

EXAMPLES = r"""
- name: Configure device credentials on Cisco DNA Center
  hosts: sandboxdnac.cisco.com
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"
    - "input.yml"
  tasks:
    - name: Get Device info and updating access point details
      cisco.dnac.accesspoint_workflow_manager:
        display_selection: "{{display_selection}}"
        device_filterfield: "{{device_filterfield}}"
        device_filter_string: "{{device_filter_string}}"
        device_fields: "{{device_fields}}"
        ap_selected_field: "{{ap_selected_field}}"
        dnac_host: "{{dnac_host}}"
        dnac_username: "{{dnac_username}}"
        dnac_password: "{{dnac_password}}"
        dnac_verify: "{{dnac_verify}}"
        dnac_port: "{{dnac_port}}"
        dnac_version: "{{dnac_version}}"
        dnac_debug: "{{dnac_debug}}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: True
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        accesspoints: "{{ accesspoints }}"
      register: output_list
    - name: iterate through module output (a list)
      debug:
        msg: '{{ item }}'   
        with_items: "{{output_list.output }}"
"""

RETURN = r"""
#Case: Modification of the AP details updated and Rebooted Accesspoint
response:
  description: A dictionary with activation details as returned by the Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
        "response": {
            "taskId": "string",
            "url": "string"
        },
        "version": "string"
    }
"""

class DnacAutomation(DnacBase):
    """Class containing member attributes for DNAC Access Point Automation module"""

    def __init__(self, module):
        super().__init__(module)
        self.result["response"] = []
        self.supported_states = ["merged"]
        self.payload = module.params
        self.baseurl = "https://" + module.params["dnac_host"]+ ":" + module.params["dnac_port"]
        self.log('Login DNAC using by user: ' + module.params["dnac_username"], "INFO")
        try:
            self.dnac = api.DNACenterAPI(base_url=self.baseurl, 
                                    username = module.params["dnac_username"],
                                    password = module.params["dnac_password"],
                                    verify = False)
        except Exception as e:
            self.log("Unable to Login DNAC "+ str(e) , "ERROR")

    # Below function used pydentic validation over the ansible validation
    # We can customize validation, if it not required we can remove this function.
    def validate_input(self, inputdata):
        """
        Validate the fields provided in the yml files.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types based pydentics package.
        Parameters:
          - inputdata: To validate the input file of yaml keys values will be validated.
        Returns:
          The method not returns anything just validation input if anything worng will stop execution.
        Example:
            To use this method, create an instance of the class and call 'validate_input' on it.
          If the validation succeeds, this will allow to go next step, unless this will stop execution.
          based on the fields.
        """
        self.log('Validating the Yaml File..', "INFO")
        try:
            CheckUrl(hosturl="https://" + inputdata["dnac_host"])
            CheckNames(names=inputdata["dnac_username"])
            CheckNames(names=inputdata["dnac_password"])
            CheckPort(port=inputdata["dnac_port"])
            aplist = inputdata.get("accesspoints")
            for eachap in aplist:
                CheckIPaddress(managementIpAddress=eachap["managementIpAddress"])
                CheckMACaddress(macAddress=eachap["macAddress"])
                CheckRadioType(ap_radiotype=int(eachap["accesspointradiotype"]))
            self.log("Successfully validated playbook config ", "INFO")
            self.msg = "Successfully validated input from the playbook"
            self.status = "success"
            return self
        except ValidationError as e:
            self.log("Invalid Param provided in input Yml File." + str(e), "ERROR")
            self.msg = "Invalid parameters in playbook: " + str(e)
            self.status = "failed"
            return self

    # below function not required for the current scenario but required for upcomming. 
    def get_state(self):
        """
        This function used to get all device details as json response from DNAC site.
        This will work based on the input yml file
        Parameters:
          - No Parameters required
        Returns:
          {
            'family': 'Switches and Hubs', 'type': 'Cisco Catalyst 9000 UADP 8 Port Virtual Switch',
            'description': 'Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9KV_IOSXE), Experimental Version 17.9.20220318:182713 [BLD_POLARIS_DEV_S2C_20220318_081310-10-g847b433944c4:/nobackup/rajavenk/vikagarw/git_ws/polaris_dev 101] Copyright (c) 1986-2022 by Cis', 4
            'lastUpdateTime': 1713755121303, 'macAddress': '52:54:00:01:c2:c0', 
            'deviceSupportLevel': 'Supported', 'softwareType': 'IOS-XE', 'softwareVersion': '17.9.20220318:182713', 'serialNumber': '9SB9FYAFA2O', 'collectionInterval': 'Global Default', 'managementState': 'Managed', 'upTime': '28 days, 0:13:42.00', 'roleSource': 'AUTO', 'lastUpdated': '2024-04-22 03:05:21', 'bootDateTime': '2024-03-25 02:52:21', 'series': 'Cisco Catalyst 9000 Series Virtual Switches', 'snmpContact': '', 'snmpLocation': '', 'apManagerInterfaceIp': '', 'collectionStatus': 'Partial Collection Failure', 'hostname': 'sw1', 'locationName': None, 'managementIpAddress': '10.10.20.175', 'platformId': 'C9KV-UADP-8P', 'reachabilityFailureReason': 'SNMP Connectivity Failed', 'reachabilityStatus': 'Unreachable', 'associatedWlcIp': '', 'apEthernetMacAddress': None, 'errorCode': 'DEV-UNREACHED', 'errorDescription': 'NCIM12013: SNMP timeouts are occurring with this device. }
        Example:
            functions = DnacAutomation(module)
            device_data = functions.get_network_info()
        """
        self.log('Getting Network Device information', "INFO")
        try:
            devices = self.dnac.devices.get_device_list()
            dnac_data = self.parse_json_data(devices.response, self.payload)
            responses = {}
            responses["accesspoints"] = {"response": dnac_data,
                         "msg": "DNAC Device data list"}
            self.result["response"].append(responses)
            return dnac_data
        except Exception as e:
            self.log("Unable to get device info "+ str(e) , "ERROR")

    def parse_json_data(self, json_data, payload):
        """
        This function used from inside the get_network_info function for customize the dnac device information data
        based on the display_selection number it should be 1,2,3,4or 5 
        display_selection : 1 :-
            This will show the all fields of the device info no filter
        display_selection : 2 :-
            This will show only filtered data based on the specific field mentioned in the urls.yml
            device_filterfield: "hostname"  # single field no comma
            device_filter_string: "sw2,sw1" # Full value like 'hostname': 'sw3'
        display_selection : 3 :-
            This will show only the fields need to be displayed from the device data no filter will be applied
            any customization required can update in the urls.yml file
            device_fields: "id,family,type,macAddress,managementIpAddress"
        display_selection : 4 :-
            This field combination of the 2 and 3, when used 4 need to give all below 3 fields
            device_filterfield: "hostname"  # single field no comma
            device_filter_string: "sw2,sw1" # Full value like 'hostname': 'sw3'
            device_fields: "id,family,type,macAddress,managementIpAddress"
        display_selection : 5 :-
            This field combination of 2 & 3 also multiple field can be filtered  used pandas package
            device_fields: "id,family,type,macAddress,managementIpAddress" # this must be given
            device_filterfield: "hostname,macAddress" # List of field need to be filter given by comma seperater
            device_filter_string: "sw2,sw1|52:54:00:0e:1c:6a" # added | seperated based on the list of field need filter
        Parameters:
          - json_data: this is respose of the all device details geting from device info url. 
          - payload: used from yml input files like, urls.yml, credentials.yml and input.yml
        Returns:
            {
            'id': 'c069bc2c-bfa3-47ef-a37e-35e2f8ed3f01'
            'family': 'Switches and Hubs',
            'type': 'Cisco Catalyst 9000 UADP 8 Port Virtual Switch',
            'macAddress': '52:54:00:01:c2:c0', 
            'managementIpAddress': '10.10.20.175'
            }
        Example:
            self.parse_json_data(jsondata, payload)
        """
        if payload['display_selection'] == 1:
            return json_data
        elif payload['display_selection'] == 2:
            field = payload['device_filterfield']
            types = [str(x) for x in payload['device_filter_string'].split(",")]
            if field != None:
                filtered_data = [data for data in json_data if data[field] in types]
                return filtered_data
            else:
                self.log('No data in filterfield', "ERROR")
                return None
        elif payload['display_selection'] == 3:
            fields = [str(x) for x in payload['device_fields'].split(",")]
            df = pd.DataFrame.from_records(json_data)
            selected_fields = df[fields]
            return selected_fields.to_dict('records')
        elif payload['display_selection'] == 4:
            fields = [str(x) for x in payload['device_fields'].split(",")]
            field = payload['device_filterfield']
            types = [str(x) for x in payload['device_filter_string'].split(",")]
            if field != None:
                filtered_data = [data for data in json_data if data[field] in types]
                if len(fields) > 0:
                    new_list = []
                    for data in filtered_data:
                        new_dict = {key: value for key, value in data.items() if key in fields}
                        new_list.append(new_dict)
                    return new_list
                else:
                    self.log('No data in field', "ERROR")
                    return None
        elif payload['display_selection'] == 5:
            fields = [str(x) for x in payload['device_fields'].split(",")]
            ffield = [str(x) for x in payload['device_filterfield'].split(",")]
            types = [str(x) for x in payload['device_filter_string'].split("|")]
            df = pd.DataFrame.from_records(json_data)
            count = 0
            for field in ffield:
                eachtypes = [str(x) for x in types[count].split(",")]
                df = df[df[field].isin(eachtypes)]
                count += 1
            selected_fields = df[fields]
            return selected_fields.to_dict('records')

    def get_have(self):
        ap_data = self.get_ap_configuration()
        final_ap_data = self.compare_ap_cofig_with_inputdata(ap_data)

        responses = {}
        responses["accesspoints"] = {"response": final_ap_data,
            "msg": "Filtered AP Device data list for update AP config"}
        self.result["response"].append(responses)
        return final_ap_data

    def get_ap_configuration(self):
        """
        This function used to get AP device details as json response from DNAC site.
        by giving MAC address as a input in the URL GET Method
        Parameters:
            We are not using input param already passed in the module.param
          - self.payload: used from yml input files input.yml we are using accesspoints section
            if ap_selected_field in input.yml is empty or all this will show all field
            else ap_selected_field: "macAddress,displayName,apMode,apName"
            then will show only listed field.
        Returns:
            {
                "macAddress": '52:54:00:01:c2:c0',
                "apName": "string",
                "displayName": "string",
                "apMode": "string"
            }
        Example:
            functions = DnacAutomation(module)
            ap_data = functions.get_ap_configuration()
        """
        ap_config_data = []
        for device in self.payload["accesspoints"]:
            self.log('Getting Access Point Configuration Information' + device['macAddress'], "INFO")
            try:
                # Below code might change once we receive the dev dnac credentials
                jsondata = self.dnac.wireless.get_access_point_configuration(macAddress = device['macAddress'])
                ap_config_data.append(jsondata.response)
            except Exception as e:
                self.log(jsondata['error'] + e, "ERROR")
        if self.payload["ap_selected_field"] == "" or self.payload["ap_selected_field"] == "all" : return ap_config_data
        fields = [str(x) for x in self.payload["ap_selected_field"].split(",")]
        if len(ap_config_data) != 0:
            df = pd.DataFrame.from_records(ap_config_data)
            selected_data = df[fields]
            return selected_data.to_dict('records')
        else:
            return None

    def compare_ap_cofig_with_inputdata(self, apconfig):
        """
        This function used to compare with the input ap detail with the current ap configuration
        information are not same, those data will be updated in the AP input information.
        Parameters:
          - apconfig: This is response of the get_ap_configuration
        Returns:
            This will be the return the final data for update AP detail.
            [{
                "macAddress": "52:54:00:0f:25:4c",
                "managementIpAddress": "10.10.20.178",
                "accesspointradiotype": 1,
                "apName": "HallAP"},
                {"macAddress": "52:54:00:0e:1c:6a",
                "managementIpAddress": "10.10.20.176",
                "accesspointradiotype": 2,
                "apName": "FloorAP"}]
        Example:
            functions = DnacAutomation(module)
            final_input_data = functions.compare_ap_cofig_with_inputdata(all_apconfig)
        """
        final_apchange = []
        for each_input in self.payload["accesspoints"]:
            for eachap in apconfig:
                # We are identifing AP based on the AP mac Address so we cannot update this field.
                if each_input["macAddress"] == eachap["macAddress"]:
                    for each_key in list(each_input.keys()):
                        if each_input[each_key] != eachap[each_key]:
                            final_apchange.append(each_input)
                            break
        if len(final_apchange) > 0:
            return final_apchange
        else:
            self.log('Input Access Point Configuration remains same in the Current AP configration', "INFO")
            exit()

    def get_want(self, device_data):
        update_apconfig = self.update_ap_configuration(device_data)
        reboot_response = self.reboot_ap_configuration(update_apconfig)
        responses = {}
        responses["accesspoints"] = {"response": reboot_response,
            "msg": "Below list APs rebooted successfully"}
        self.result["response"].append(responses)
        return reboot_response

    def update_ap_configuration(self, device_data):
        """
        This function used to update the ap detail with the current ap configuration
        Final data received from compare_ap_cofig_with_inputdata response will be the 
        input of this function.
        Parameters:
          - device_data: DNAC final device data response from compare_ap_cofig_with_inputdata
        Returns:
            {
                "response": {
                    "taskId": "string",
                    "url": "string"
                },
                "version": "string"
            }
        Example:
            functions = DnacAutomation(module)
            final_input_data = functions.update_ap_configuration(device_data)
        """
        all_response = []
        for device in device_data:
            try:
                self.log("Updating Access Point Configuration Information of " + device["managementIpAddress"], "INFO")
                # Below code might changed once we receive the dev dnac credentials
                response = self.dnac.wireless.configure_access_points(**device)
                if response.get("Status") == 200:
                    device["update_status"] == "success"
                    all_response.append(device)
            except Exception as e:
                self.log(str(response['error']) + e, "ERROR")

        if len(all_response) > 0:
            return all_response
        else:
            return None

    def reboot_ap_configuration(self, device_data):
        """
        This function used to reboot the ap after updated the ap information.
        Parameters:
          - device_data: DNAC final device data response from update_ap_configuration
            in data of device["update_status"] == success then only this will reboot device.
        Returns:
            {
                "response": {
                    "taskId": "string",
                    "url": "string"
                },
                "version": "string"
            }
        Example:
            functions = DnacAutomation(module)
            final_input_data = functions.reboot_ap_configuration(device_data)
        """
        response = None
        all_macaddress = []

        for device in device_data:
            if device["update_status"] == "success":
                all_macaddress.append(device["apMacAddresses"])

        if len(all_macaddress) > 0:
            try:
                self.log('Rebooting below Access Point(s)' + str(all_macaddress.join(", ")), "INFO")
                # Below code might change once we receive the dev dnac credentials
                response = self.dnac.wireless.reboot_access_points(apMacAddresses = all_macaddress)
            except Exception as e:
                self.log(str(response['error']) + e, "ERROR")

        if response.get("Status") == 200:
            self.log('Rebooted below Access Point(s)' + str(all_macaddress.join(", ")), "INFO")
            return response
        else:
            return None


def main():
    """ main entry point for module execution
    """
    # Basic Ansible type check or assign default.
    element_spec = {'dnac_host': {'required': True, 'type': 'str'},
                    'dnac_port': {'type': 'str', 'default': '443'},
                    'dnac_username': {'type': 'str', 'default': 'admin'},
                    'dnac_password': {'type': 'str', 'no_log': True},
                    'display_selection': {'required': True, 'type': 'int'},
                    'device_filterfield': {'required': True, 'type': 'str'},
                    'device_filter_string': {'required': True, 'type': 'str'},
                    'device_fields': {'required': True, 'type': 'str'},
                    'ap_selected_field': {'required': True, 'type': 'str'},
                    'dnac_verify': {'type': 'bool', 'default': 'True'},
                    'dnac_version': {'type': 'str', 'default': '2.2.3.3'},
                    'dnac_debug': {'type': 'bool', 'default': False},
                    'dnac_log': {'type': 'bool', 'default': False},
                    'dnac_log_level': {'type': 'str', 'default': 'WARNING'},
                    "dnac_log_file_path": {"type": 'str', "default": 'dnac.log'},
                    'config_verify': {'type': 'bool', "default": False},
                    "dnac_log_append": {"type": 'bool', "default": True},
                    'dnac_api_task_timeout': {'type': 'int', "default": 1200},
                    'dnac_task_poll_interval': {'type': 'int', "default": 2},
                    'accesspoints': {'required': True, 'type': 'list', 'elements': 'dict'},
                    'validate_response_schema': {'type': 'bool', 'default': True}
                }
    module = AnsibleModule(
        argument_spec=element_spec,
        supports_check_mode=True
    )

    ccc_network = DnacAutomation(module)

    # Check the Input file should not be empty accesspoints param
    if len(module.params.get('accesspoints')) < 1:
        module.fail_json(msg='Access Point Should not be Empty, You may forget to pass input.yml file', **result)

    ccc_network.validate_input(module.params).check_return_status()
    
    # Get the Device data from DNAC based on the input.yaml details.
    device_data = ccc_network.get_state()

    """
    # Getting the AP details by passing the Mac Address of the device
    # Comparing input data with current AP configuration detail
    final_config = ccc_network.get_have()

    # Updating the final filtered data to the update AP information
    # Calling Reboot AP configuration.
    reboot_response = ccc_network.get_want(final_config)
    """
    module.exit_json(**ccc_network.result)

if __name__ == '__main__':
    main()