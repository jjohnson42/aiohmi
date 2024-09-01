# Copyright 2019 Lenovo Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import aiohmi.redfish.oem.generic as generic
from aiohmi.redfish.oem.lenovo import tsma
from aiohmi.redfish.oem.lenovo import xcc


def get_handler(sysinfo, sysurl, webclient, cache, cmd):
    leninf = sysinfo.get('Oem', {}).get('Lenovo', {})
    mgrinfo = {}
    if leninf:
        mgrinf, status = webclient.grab_json_response_with_status('/redfish/v1/Managers/1')
        if status != 200:
            mgrinfo = {}
    if not leninf:
        bmcinfo = cmd.bmcinfo
        if 'Ami' in bmcinfo.get('Oem', {}):
            return tsma.TsmHandler(sysinfo, sysurl, webclient, cache)
    elif 'xclarity controller' in mgrinf.get('Model', '').lower():
        if mgrinf['Model'].endswith('3'):
            return xcc3.OEMHandler(sysinfo, sysurl, webclient, cache,
                                   gpool=cmd._gpool)
        else:
            return xcc.OEMHandler(sysinfo, sysurl, webclient, cache,
                                  gpool=cmd._gpool)
    elif 'FrontPanelUSB' in leninf or 'USBManagementPortAssignment' in leninf or sysinfo.get('SKU', '').startswith('7X58'):
        return xcc.OEMHandler(sysinfo, sysurl, webclient, cache,
                              gpool=cmd._gpool)
    else:
        leninv = sysinfo.get('Links', {}).get('OEM', {}).get(
            'Lenovo', {}).get('Inventory', {})
        if 'hdd' in leninv and 'hostMAC' in leninv and 'backPlane' in leninv:
            return tsma.TsmHandler(sysinfo, sysurl, webclient, cache,
                                   gpool=cmd._gpool)
        return generic.OEMHandler(sysinfo, sysurl, webclient, cache,
                                  gpool=cmd._gpool)
