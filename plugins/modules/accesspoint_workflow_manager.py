#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
__author__ = ("A Mohamed Rafeek, Natarajan")

DOCUMENTATION = r"""
---
module: accesspoint_workflow_manager
short_description: accesspoint_workflow_manager used to automate bulk AP configuration changes.
description:
- We can change the AP display name, AP name or Other Param based on the input.yml file
- Using by this package we can filter specific device details like hostname = Switches and Hubs
- We can compare input details with current AP configuration.
- Desired configuration will be updated to the needed APs Only
version_added: '6.6.0'
extends_documentation_fragment:
  - cisco.dnac.accesspoint_workflow_manager
author: A Mohamed Rafeek (@mohamedrafeek)
        Natarajan (@natarajan)

options:
    config_verify:
        description: Set to True to verify the Cisco Catalyst Center config after applying the playbook config.
    type: bool
    default: False
    state:
        description: The state of Cisco Catalyst Center after module completion.
    type: str
    choices: [ merged ]
    default: merged

  config:
    description: List of details of AP being managed
    type: list
    elements: dict
    required: True
    suboptions:
    display_fields:
      device_fields:
        description: This is a optional field, if you want to see only few param
            from the device details you can mention those field in this list.
            each field need to mention with , seperation not space before or after ,
            if this fields not defined then default will show all field param
            eg : device_fields: "id,hostname,family,type,mac_address,management_ip_address,ap_ethernet_mac_address,last_updated,up_time"
        type: str
        required: False
      ap_selected_field:
        description: This is a optional field, if you want to see only few param
            from the Accesspoint config details, then you can mention those field
            in this list. each field need to mention with , seperation not space before or after ,
            if this fields not defined then default will show all field param
            eg : ap_selected_field: "mac_address,eth_mac,ap_name,led_brightness_level,led_status,location"
        type: str
        required: False

      Unchangable Params are below any one of the below 4 is required.
    config_devices:
      mac_address:
        description: This is MAC Address Field use to identify the devices
            from the device detail we have used to get the AP Details
            (also it is Required or Hostname Required), This field cannot be mofidied.
            MAC Address format should be eg: mac_address: "90:e9:5e:03:f3:40"
        type: str
        default: False
      hostname:
        description: This is name of device if MAC address not known
            Then hostname can be used to indentify the device
            eg : hostname: "NFW-AP1-9130AXE"
        type: str
        default: False
      management_ip_address:
        description: This param used to indetify the devices based on IP address
            from the device detail we have used to get the AP Details
            eg: management_ip_address: "204.192.6.200"
        type: str
        default: False
      family:
        description: This param used to get all devices which is belong to this family
            also when we use family param to identify, you have to use only few changes
            of AP param can be changed like change all led_brightness param to 8 in config
            eg : family: "Unified AP"
        type: str
        default: False

      below list of AP Config param can be changes based on the requirement
      ap_name:
        description: AP Name changes, we need to provide the current name
            of AP need to give in this field also ap_name_new also need to give.
            unless the AP name never change.
            eg : ap_name: "Test2"
                 ap_name_new: "NFW-AP1-9130AXE"
        type: str
        default: False
      ap_name_new:
        description: AP Name name changes new name need to be added in this field.
            we need to provide along with AP Name. so that able to change the AP Name
            eg : ap_name: "Test2"
                 ap_name_new: "NFW-AP1-9130AXE"
        type: str
        default: False
      led_brightness_level:
        description: AP LED brightness level field also able to modify by update
            this field. Brightness level from 1 to 10.
            eg : led_brightness_level: 3
        type: int
        default: False
      led_status:
        description: AP LED light need to enable or disable based on this param update.
            this will accept only 2 state "Enabled" or "Disabled"
            eg : led_status: "Enabled"
        type: str
        default: False
      location:
        description: Changing the location name of the AP, need to provide the data
            in case changes required.
            eg: location: "Bangalore"
        type: str
        default: False

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
        config: "{{ config }}"
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

import re
from dnacentersdk import api
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    validate_int,
    validate_str
)
from ansible.module_utils.basic import AnsibleModule


class Accesspoint(DnacBase):
    """Class containing member attributes for DNAC Access Point Automation module"""

    def __init__(self, module):
        super().__init__(module)
        self.result["response"] = []
        self.supported_states = ["merged"]
        self.payload = module.params
        self.keymap = {}
        self.baseurl = "https://" + module.params["dnac_host"]+ ":" + module.params["dnac_port"]
        self.log('Login DNAC using by user: ' + module.params["dnac_username"], "INFO")
        try:
            self.dnacsdk = api.DNACenterAPI(base_url=self.baseurl,
                                    username = module.params["dnac_username"],
                                    password = module.params["dnac_password"],
                                    verify = False)
            
        except Exception as e:
            self.log("Unable to Login DNAC "+ str(e) , "ERROR")

    # Below function used to validate input over the ansible validation
    def validate_input_yml(self, inputdata):
        """
        Validate the fields provided in the yml files.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types based on input.
        Parameters:
          - inputdata: To validate the input file of yaml keys values will be validated.
        Returns:
          The method not returns anything just validation input if anything worng will stop execution.
        Example:
            To use this method, create an instance of the class and call 'validate_input_yml' on it.
          If the validation succeeds, this will allow to go next step, unless this will stop execution.
          based on the fields.
        """
        self.log('Validating the Yaml File..', "INFO")
        try:
            errormsg = []
            aplist = inputdata.get("config").get("config_devices")
            for eachap in aplist:
                temp_spec = dict(eachap=dict(type='dict'))
                eachap = self.camel_to_snake_case(eachap)
                accesspoint_spec = dict(mac_address=dict(type='str'),
                           led_brightness_level=dict(type='int'),
                           led_status = dict(type='str'),
                           location = dict(type='str'),
                           ap_name = dict(type='str'),
                           ap_name_new = dict(type='str'),
                           management_ip_address = dict(type='str'),
                           hostname = dict(type='str'),
                           )
                valid_param, invalid_param = validate_list_of_dicts(eachap, accesspoint_spec)
                if len(invalid_param) > 0:
                    errormsg.append("Invalid param found '{0}' in input"\
                                    .format(", ".join(invalid_param)))

                if eachap.get("mac_address"):
                    mac_regex = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
                    if not mac_regex.match(eachap["mac_address"]):
                        errormsg.append("mac_address : Invalid MAC Address '{0}' in input."\
                                        .format(eachap["mac_address"]))

                if eachap.get("management_ip_address"):
                    if not self.is_valid_ipv4(eachap["management_ip_address"]):
                        errormsg.append("management_ip_address: Invalid Management IP Address '{0}' in input"\
                                        .format(eachap["management_ip_address"]))

                if eachap.get("led_brightness_level"):
                    if eachap["led_brightness_level"] not in range(1,11):
                        errormsg.append("led_brightness_level: Invalid LED Brightness level '{0}' in input"\
                                        .format(eachap["led_brightness_level"]))

                if eachap.get("led_status") and eachap.get("led_status") not in ("Disabled", "Enabled"):
                    errormsg.append("led_status: Invalid LED Status '{0}' in input"\
                                    .format(eachap["led_status"]))

                if eachap.get("ap_name"):
                    param_spec = dict(type = "str", length_max = 32)
                    validate_str(eachap["ap_name"], param_spec, "ap_name",
                                  errormsg)

                if eachap.get("ap_name_new"):
                    param_spec = dict(type = "str", length_max = 32)
                    validate_str(eachap["ap_name_new"], param_spec, "ap_name_new",
                                  errormsg)

                if eachap.get("location"):
                    param_spec = dict(type = "str", length_max = 255)
                    validate_str(eachap["location"], param_spec, "location",
                                  errormsg)

                if len(errormsg) > 0:
                    self.log("Invalid Input in input file: '{0}' ".format(str("\n".join(errormsg))), "ERROR")
                    self.module.fail_json(msg=str("\n".join(errormsg)))

        except Exception as e:
            self.log("Invalid Param provided in input Yml File. {0}".format(str(e)), "ERROR")
            self.msg = "Invalid parameters in playbook: {0}".format(str("\n".join(errormsg)))
            self.status = "failed"
            return self

    def get_state(self):
        """
        This function used to get device details as json response from DNAC site based
        on the config field given on the input yml file
        Parameters:
          - config:
            -   mac_address: "90:e9:5e:03:f3:40" (Required Field)
                led_brightness_level: 4 
                led_status: "Enabled"
                location: "LTTS"
                ap_name: "NFW-AP1-9130AXE"
        Returns:
            {
                "apEthernetMacAddress": "34:5d:a8:0e:20:b4",
                "family": "Unified AP",
                "hostname": "NFW-AP1-9130AXE",
                "id": "37b05b0f-1b1e-496a-b101-8f277f0af8ff",
                "lastUpdated": "2024-05-28 08:36:19",
                "macAddress": "90:e9:5e:03:f3:40",
                "managementIpAddress": "204.1.216.2",
                "type": "Cisco Catalyst 9130AXE Unified Access Point",
                "upTime": "08:22:37.080"
            }
        Example:
            functions = Accesspoint(module)
            device_data = functions.get_state()
        """
        self.log('Getting Network Device information', "INFO")
        try:
            all_devices = self.payload["config"]["config_devices"]
            all_mac_address = [eachdevice["mac_address"] \
                               for eachdevice in all_devices \
                               if eachdevice.get("mac_address") is not None]
            all_hosts = [eachdevice["hostname"] for eachdevice in all_devices \
                               if eachdevice.get("hostname") is not None]
            all_management_ip_address = [eachdevice["management_ip_address"] \
                                       for eachdevice in all_devices \
                                        if eachdevice.get("management_ip_address") is not None]
            all_family = [eachdevice["family"] for eachdevice in all_devices \
                               if eachdevice.get("family") is not None]

            searchparam = dict(mac_address = all_mac_address if len(all_mac_address) > 0 else None,
                               hostname = all_hosts if len(all_hosts) > 0  else None,
                               management_ip_address = all_management_ip_address \
                                if len(all_management_ip_address) > 0 else None,
                               family = all_family if len(all_family) > 0 else None)
            device_list = self.dnacsdk.devices.get_device_list(**searchparam)

            device_fields = self.payload["config"]["display_fields"]["device_fields"]
            if device_fields == "" or device_fields == "all":
                self.payload["device_list"] = device_list['response']
                self.payload["device_list"] = self.camel_to_snake_case(self.payload["device_list"])
            else:
                self.payload["device_list"]=self.data_frame(device_fields,device_list['response'])
            return self.payload["device_list"]
        except Exception as e:
            self.log("Unable to get device info "+ str(e) , "ERROR")

    # Below function used to show the current state of the network divices
    # As Accesss point Device info, Config and Final field to pass in the Update data
    def get_have(self):
        """
        This function used to get AP device details as json response from DNAC site.
        by giving MAC address as a input in the URL GET Method
        parameters:
          key = ap_ethernet_mac_address from the device list
        returns:
          This will return the filtered data.
        Device information given in the input file
        Device Configuration Details 
        Conpare with input data and current config data
        """
        responses = {}
        ap_data = []
        final_ap_data = []
        ap_data = self.get_ap_configuration()
        final_ap_data = self.compare_ap_cofig_with_inputdata(ap_data)
        # If the final_ap_data is None means no changes required to update
        if final_ap_data is None:
            responses["accesspoint"] = dict(
                device_list= self.payload["device_list"],
                accesspoint_config=ap_data,
                final_input=final_ap_data,
                msg="Input Access Point Configuration remain same in Current AP configration")
            del self.payload["device_list"]
            self.result["skipped"] = True
        else:
            responses["accesspoint"] = {
                "device_list": self.payload["device_list"],
                "device_configs": ap_data,
                "final_input": final_ap_data,
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
            else ap_selected_field: "mac_address,eth_mac,ap_name,led_status,location"
            then will show only listed field.
        Returns:
            [
                {
                    "apName": "NFW-AP1-9130AXE",
                    "ethMac": "34:5d:a8:0e:20:b4",
                    "ledBrightnessLevel": 3,
                    "ledStatus": "Enabled",
                    "location": "LTTS",
                    "macAddress": "90:e9:5e:03:f3:40"
                }
            ]
        Example:
            functions = Accesspoint(module)
            ap_data = functions.get_ap_configuration()
        """
        ap_config_data = []
        for device in self.payload["device_list"]:
            self.log('Getting Access Point Configuration Information for ' \
                     + device['ap_ethernet_mac_address'], "INFO")
            try:
                jsondata = self.dnacsdk.wireless.get_access_point_configuration(
                    key=str(device['ap_ethernet_mac_address']))
                ap_config_data.append(jsondata)
            except Exception as e:
                self.log(jsondata['error'] + e, "ERROR")

        self.keymap = self.keymaping(self.keymap, ap_config_data[0])

        ap_selected_field = self.payload["config"]["display_fields"]["ap_selected_field"]
        if ap_selected_field == "" or ap_selected_field == "all":
            return ap_config_data
        return  self.data_frame(ap_selected_field, ap_config_data)

    def compare_ap_cofig_with_inputdata(self, apconfig):
        """
        This function used to compare with the input ap detail with the current ap configuration
        information are not same, those data will be updated in the AP input information.
        Parameters:
          - apconfig: This is response of the get_ap_configuration
        Returns:
            This will be the return the final data for update AP detail.
            "final_input": [
                {
                    "adminStatus": true,
                    "apList": [
                        {
                            "macAddress": "34:5d:a8:0e:20:b4"
                        }
                    ],
                    "configureLedBrightnessLevel": true,
                    "ledBrightnessLevel": 4,
                    "macAddress": "34:5d:a8:0e:20:b4"
                } ]
        Example:
            functions = Accesspoint(module)
            final_input_data = functions.compare_ap_cofig_with_inputdata(all_apconfig)
        """
        apconfig = self.camel_to_snake_case(apconfig)
        final_apchange = []
        for each_input in self.payload["config"]["config_devices"]:
            for eachap in apconfig:
                if each_input.get("mac_address") == eachap["mac_address"] or \
                    each_input.get("hostname") == eachap["ap_name"]:
                    newdict = {}
                    allkey = list(each_input.keys())
                    for value in ("mac_address","hostname","management_ip_address", "family"):
                        if value in allkey: allkey.remove(value)
                    for each_key in allkey:
                        if each_key == "ap_name_new":
                            if each_input["ap_name_new"] != eachap.get("ap_name"):
                                newdict["apNameNew"] = each_input["ap_name_new"]
                        elif each_key == "ap_name":
                            newdict[self.keymap[each_key]] = each_input[each_key]
                        else:
                            if each_input[each_key] != eachap[each_key]:
                                newdict[self.keymap[each_key]] = each_input[each_key]
                    if newdict.get("apName") is not None and newdict.get("apNameNew") is None:
                        del newdict["apName"]
                    if newdict:
                        newdict["macAddress"] = eachap["eth_mac"]
                        final_apchange.append(newdict)
        if len(final_apchange) > 0:
            return final_apchange
        else:
            self.log('Input Access Point Configuration remain same in Current AP configration',
                      "INFO")
            return None

    def get_want(self, device_data):
        """
        This Function used to Update data or Create the data in DNAC
        or update the data to server below list of action in this function.
        Update AP configuration
        Check the Task Status 
        """
        update_apconfig = self.update_ap_configuration(device_data)
        taskdetails = []
        if len(update_apconfig) > 0:
            for eachtask in update_apconfig:
                task = self.check_task_response_status(eachtask,"task_intent", True)
                taskdetails.append(task)
            devices_config = self.get_ap_configuration()
            responses = {}
            responses["accesspoints_updates"] = {"response": taskdetails,
                                             "after_update": devices_config,
            "msg": "Below list APs updated successfully"}
            self.result["changed"] = True
            del self.payload["device_list"]
            self.result["response"].append(responses)
            return update_apconfig

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
            functions = Accesspoint(module)
            final_input_data = functions.update_ap_configuration(device_data)
        """
        all_response = []
        for device in device_data:
            try:
                self.log("Updating Access Point Configuration Information "+ device["macAddress"],
                          "INFO")
                # Below code might changed once we receive the dev dnac credentials
                device["adminStatus"] = True
                if device.get("apName") is not None:
                    device["apList"] = [dict(apName = device["apName"],
                                        apNameNew = device["apNameNew"],
                                        macAddress = device["macAddress"])]
                    del device["apName"]
                    del device["apNameNew"]
                elif device.get("apName") is None and device.get("macAddress") is not None:
                    device["apList"] = [dict(macAddress = device["macAddress"])]

                if device.get("location") is not None:
                    device["configureLocation"] = True
                if device.get("ledBrightnessLevel") is not None:
                    device["configureLedBrightnessLevel"] = True
                if device.get("ledStatus") is not None:
                    device["configureLedStatus"] = True
                    device["ledStatus"] = True if device["ledStatus"] == "Enabled" else False

                for rmkey in ("mac_address", "hostname", "management_ip_address"):
                    if device.get(rmkey): del device[rmkey]
                
                response = self.dnacsdk.wireless.configure_access_points(**device)
                self.log("Response of Access Point Configuration: " + str(response["response"]), "INFO")
                all_response.append(dict(macAdress=device["macAddress"], response=response["response"]))
            except Exception as e:
                self.log("AP config update Error" + device["macAddress"] + str(e), "ERROR")

        if len(all_response) > 0:
            return all_response

    def data_frame(self, fieldlist = None, data = list):
        """
        This function used to give output as limited field to show for given in the fieldlist
        need to pass the list of field need to show with , separated string value also need
        to pass the data as device list or device config list as input
        Parameters:
          - fieldlist: (str) key need to display the value.
            eg : device_fields: "id,hostname,family,type,mac_address,up_time"
          - data: (list of dict) Device list or Config list
        Returns:
            {
                "family": "Unified AP",
                "hostname": "LTTS-Test2",
                "id": "34f5a410-413d-4a6c-b195-8267fd599491",
                "last_updated": "2024-06-05 13:06:24",
                "mac_address": "34:5d:a8:3b:d8:e0",
                "up_time": "7 days, 13:07:00.020"
            }
        Example:
            functions = Accesspoint(module)
            final_input_data = functions.data_frame(device_fields, device_data)
        """
        try:
            data = self.camel_to_snake_case(data)
            if len(data) != 0 and fieldlist is not None:
                fields = [x for x in fieldlist.split(",")]
                dataframe = []
                for eachdata in data:
                    limitedfields = {}
                    for each_key in fields:
                        limitedfields[each_key] = eachdata[each_key]
                    dataframe.append(limitedfields)
                return dataframe
            else:
                return None
        except Exception as e:
            self.log("Unable to process Dataframe "+ str(e) , "ERROR")
            return None

    def keymaping(self, keymap = any, data = any):
        """
        This function used to create the key value by snake case and Camal Case
        we need to pass the input as the device list or AP cofig list this function collects
        all key which is in Camal case and convert the key to Snake Case 
        Snake case will be key and value will be as Camal Case return as Dict
        Parameters:
          - keymap: type Dict : Already any Key map dict was available add here or empty dict.{}
          - data: Type :Dict : Which key need do the key map use the data {}
            eg: Device list response or AP config response as a input
        Returns:
            {
                {
                    "mac_address": "macAddress",
                    "ap_name": "apName"
                }
            }
        Example:
            functions = Accesspoint(module)
            keymap = functions.keymaping(keymap,device_data)
        """
        if isinstance(data, dict):
            keymap.update(keymap)
            for key, value in data.items():
                new_key = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', key).lower()
                keymap[new_key] = key
                if isinstance(value, dict):
                    self.keymaping(keymap, value)
                elif isinstance(value, list):
                    self.keymaping(keymap, (item for item in value if isinstance(item, dict)))
            return keymap
        elif isinstance(data, list):
            self.keymaping(keymap, (item for item in data if isinstance(item, dict)))
        else:
            return keymap


def main():
    """ main entry point for module execution
    """
    # Basic Ansible type check or assign default.
    accepoint_spec = {'dnac_host': {'required': True, 'type': 'str'},
                    'dnac_port': {'type': 'str', 'default': '443'},
                    'dnac_username': {'type': 'str', 'default': 'admin'},
                    'dnac_password': {'type': 'str', 'no_log': True},
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
                    'config': {'required': True, 'type': 'dict'},
                    'validate_response_schema': {'type': 'bool', 'default': True}
                }
    module = AnsibleModule(
        argument_spec=accepoint_spec,
        supports_check_mode=True
    )

    ccc_network = Accesspoint(module)

    # Check the Input file should not be empty config param
    if len(module.params.get('config').get("config_devices")) < 1:
        module.fail_json(msg='Access Point Should not be Empty, You may forget to pass input.yml',
                         **ccc_network.result)

    ccc_network.validate_input_yml(module.params)

    # Getting AP device list based on the input as MAC Address or Host Name
    devices_list = ccc_network.get_state()
    # Check if AP list is empty due to MAC Addres might not be
    # in the given DNAC
    if devices_list is None:
        module.fail_json(msg='Given MAC Address not available in DNAC', **ccc_network.result)

    # Getting the AP details by passing the Mac Address of the device
    # Comparing input data with current AP configuration detail
    final_config = ccc_network.get_have()

    if final_config:
        # Updating the final filtered data to the update AP information
        ccc_network.get_want(final_config)

    module.exit_json(**ccc_network.result)

if __name__ == '__main__':
    main()
