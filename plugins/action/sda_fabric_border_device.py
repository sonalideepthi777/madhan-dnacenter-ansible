#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from ansible.plugins.action import ActionBase
try:
    from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
        AnsibleArgSpecValidator,
    )
except ImportError:
    ANSIBLE_UTILS_IS_INSTALLED = False
else:
    ANSIBLE_UTILS_IS_INSTALLED = True
from ansible.errors import AnsibleActionFail
from ansible_collections.cisco.dnac.plugins.plugin_utils.dnac import (
    DNACSDK,
    dnac_argument_spec,
    dnac_compare_equality,
    get_dict_result,
)
from ansible_collections.cisco.dnac.plugins.plugin_utils.exceptions import (
    InconsistentParameters,
)

# Get common arguments specification
argument_spec = dnac_argument_spec()
# Add arguments specific for this module
argument_spec.update(dict(
    state=dict(type="str", default="present", choices=["present", "absent"]),
    deviceManagementIpAddress=dict(type="str"),
    siteNameHierarchy=dict(type="str"),
    externalDomainRoutingProtocolName=dict(type="str"),
    externalConnectivityIpPoolName=dict(type="str"),
    internalAutonomouSystemNumber=dict(type="str"),
    borderSessionType=dict(type="str"),
    connectedToInternet=dict(type="bool"),
    externalConnectivitySettings=dict(type="dict"),
    interfaceName=dict(type="str"),
    externalAutonomouSystemNumber=dict(type="str"),
    l3Handoff=dict(type="dict"),
    virtualNetwork=dict(type="dict"),
    virtualNetworkName=dict(type="str"),
    vlanId=dict(type="str"),
))

required_if = [
]
required_one_of = []
mutually_exclusive = []
required_together = []


class SdaFabricBorderDevice(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            deviceManagementIpAddress=params.get("deviceManagementIpAddress"),
            siteNameHierarchy=params.get("siteNameHierarchy"),
            externalDomainRoutingProtocolName=params.get("externalDomainRoutingProtocolName"),
            externalConnectivityIpPoolName=params.get("externalConnectivityIpPoolName"),
            internalAutonomouSystemNumber=params.get("internalAutonomouSystemNumber"),
            borderSessionType=params.get("borderSessionType"),
            connectedToInternet=params.get("connectedToInternet"),
            externalConnectivitySettings=params.get("externalConnectivitySettings"),
            interfaceName=params.get("interfaceName"),
            externalAutonomouSystemNumber=params.get("externalAutonomouSystemNumber"),
            l3Handoff=params.get("l3Handoff"),
            virtualNetwork=params.get("virtualNetwork"),
            virtualNetworkName=params.get("virtualNetworkName"),
            vlanId=params.get("vlanId"),
            device_management_ip_address=params.get("deviceManagementIpAddress"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        new_object_params['device_management_ip_address'] = self.new_object.get('device_management_ip_address')
        return new_object_params

    def create_params(self):
        new_object_params = {}
        new_object_params['deviceManagementIpAddress'] = self.new_object.get('deviceManagementIpAddress')
        new_object_params['siteNameHierarchy'] = self.new_object.get('siteNameHierarchy')
        new_object_params['externalDomainRoutingProtocolName'] = self.new_object.get('externalDomainRoutingProtocolName')
        new_object_params['externalConnectivityIpPoolName'] = self.new_object.get('externalConnectivityIpPoolName')
        new_object_params['internalAutonomouSystemNumber'] = self.new_object.get('internalAutonomouSystemNumber')
        new_object_params['borderSessionType'] = self.new_object.get('borderSessionType')
        new_object_params['connectedToInternet'] = self.new_object.get('connectedToInternet')
        new_object_params['externalConnectivitySettings'] = self.new_object.get('externalConnectivitySettings')
        new_object_params['interfaceName'] = self.new_object.get('interfaceName')
        new_object_params['externalAutonomouSystemNumber'] = self.new_object.get('externalAutonomouSystemNumber')
        new_object_params['l3Handoff'] = self.new_object.get('l3Handoff')
        new_object_params['virtualNetwork'] = self.new_object.get('virtualNetwork')
        new_object_params['virtualNetworkName'] = self.new_object.get('virtualNetworkName')
        new_object_params['vlanId'] = self.new_object.get('vlanId')
        return new_object_params

    def delete_all_params(self):
        new_object_params = {}
        new_object_params['device_management_ip_address'] = self.new_object.get('device_management_ip_address')
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTICE: Does not have a get by name method, using get all
        try:
            items = self.dnac.exec(
                family="sda",
                function="gets_border_device_detail",
                params=self.get_all_params(name=name),
            )
            if isinstance(items, dict):
                if 'response' in items:
                    items = items.get('response')
            result = get_dict_result(items, 'name', name)
        except Exception:
            result = None
        return result

    def get_object_by_id(self, id):
        result = None
        # NOTE: Does not have a get by id method or it is in another action
        return result

    def exists(self):
        name = self.new_object.get("name")
        prev_obj = self.get_object_by_name(name)
        it_exists = prev_obj is not None and isinstance(prev_obj, dict) and prev_obj.get("status") != "failed"
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("deviceManagementIpAddress", "deviceManagementIpAddress"),
            ("siteNameHierarchy", "siteNameHierarchy"),
            ("externalDomainRoutingProtocolName", "externalDomainRoutingProtocolName"),
            ("externalConnectivityIpPoolName", "externalConnectivityIpPoolName"),
            ("internalAutonomouSystemNumber", "internalAutonomouSystemNumber"),
            ("borderSessionType", "borderSessionType"),
            ("connectedToInternet", "connectedToInternet"),
            ("externalConnectivitySettings", "externalConnectivitySettings"),
            ("interfaceName", "interfaceName"),
            ("externalAutonomouSystemNumber", "externalAutonomouSystemNumber"),
            ("l3Handoff", "l3Handoff"),
            ("virtualNetwork", "virtualNetwork"),
            ("virtualNetworkName", "virtualNetworkName"),
            ("vlanId", "vlanId"),
            ("deviceManagementIpAddress", "device_management_ip_address"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not dnac_compare_equality(current_obj.get(dnac_param),
                                             requested_obj.get(ansible_param))
                   for (dnac_param, ansible_param) in obj_params)

    def create(self):
        result = self.dnac.exec(
            family="sda",
            function="adds_border_device",
            params=self.create_params(),
            op_modifies=True,
        )
        return result

    def delete(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        result = self.dnac.exec(
            family="sda",
            function="deletes_border_device",
            params=self.delete_all_params(),
        )
        return result


class ActionModule(ActionBase):
    def __init__(self, *args, **kwargs):
        if not ANSIBLE_UTILS_IS_INSTALLED:
            raise AnsibleActionFail("ansible.utils is not installed. Execute 'ansible-galaxy collection install ansible.utils'")
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_async = False
        self._supports_check_mode = False
        self._result = None

    # Checks the supplied parameters against the argument spec for this module
    def _check_argspec(self):
        aav = AnsibleArgSpecValidator(
            data=self._task.args,
            schema=dict(argument_spec=argument_spec),
            schema_format="argspec",
            schema_conditionals=dict(
                required_if=required_if,
                required_one_of=required_one_of,
                mutually_exclusive=mutually_exclusive,
                required_together=required_together,
            ),
            name=self._task.action,
        )
        valid, errors, self._task.args = aav.validate()
        if not valid:
            raise AnsibleActionFail(errors)

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        dnac = DNACSDK(self._task.args)
        obj = SdaFabricBorderDevice(self._task.args, dnac)

        state = self._task.args.get("state")

        response = None
        if state == "present":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                if obj.requires_update(prev_obj):
                    response = prev_obj
                    dnac.object_present_and_different()
                else:
                    response = prev_obj
                    dnac.object_already_present()
            else:
                response = obj.create()
                dnac.object_created()
        elif state == "absent":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                response = obj.delete()
                dnac.object_deleted()
            else:
                dnac.object_already_absent()

        self._result.update(dict(dnac_response=response))
        self._result.update(dnac.exit_json())
        return self._result