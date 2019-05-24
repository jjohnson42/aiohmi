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

import pyghmi.redfish.oem.generic as generic
from pyghmi.util.parse import parse_time
import errno
import json
import socket
import pyghmi.ipmi.private.util as util
import pyghmi.exceptions as pygexc


class OEMHandler(generic.OEMHandler):

    def __init__(self, sysinfo, sysurl, webclient, cache):
        super(OEMHandler, self).__init__(sysinfo, sysurl, webclient, cache)
        self._wc = None

    def get_description(self):
        description = self._do_web_request('/DeviceDescription.json')
        if description:
            description = description[0]
        u_height = description.get('u-height', '')
        if not u_height and description.get(
                'enclosure-machinetype-model', '').startswith('7Y36'):
            u_height = '2'
        if not u_height:
            return {}
        u_height = int(u_height)
        slot = description.get('slot', '0')
        slot = int(slot)
        return {'height': u_height, 'slot': slot}

    def _get_agentless_firmware(self, components):
        adata = self.wc.grab_json_response('/api/dataset/imm_adapters?params=pci_GetAdapters')
        anames = set()
        for adata in adata.get('items', []):
            baseaname = adata['adapterName']
            aname = baseaname
            idx = 1
            while aname in anames:
                aname = '{0} {1}'.format(baseaname, idx)
                idx += 1
            anames.add(aname)
            donenames = set()
            for fundata in adata['functions']:
                for firm in fundata.get('firmwares', []):
                    fname = firm['firmwareName'].rstrip()
                    if '.' in fname:
                        fname = firm['description'].rstrip()
                    if fname in donenames:
                        # ignore redundant entry
                        continue
                    if not fname:
                        continue
                    donenames.add(fname)
                    bdata = {}
                    if 'versionStr' in firm and firm['versionStr']:
                        bdata['version'] = firm['versionStr']
                    if ('releaseDate' in firm and
                            firm['releaseDate'] and
                            firm['releaseDate'] != 'N/A'):
                        try:
                            bdata['date'] = parse_time(firm['releaseDate'])
                        except ValueError:
                            pass
                    yield ('{0} {1}'.format(aname, fname), bdata)
    
    def _get_disk_firmware_single(self, diskent, prefix=''):
        bdata = {}
        if not prefix and diskent.get('location', '').startswith('M.2'):
            prefix = 'M.2-'
        diskname = 'Disk {1}{0}'.format(diskent['slotNo'], prefix)
        bdata['model'] = diskent[
            'productName'].rstrip()
        bdata['version'] = diskent['fwVersion']
        return (diskname, bdata)
    def _get_disk_firmware(self, coponents):
        storagedata = storagedata = self.wc.grab_json_response(
            '/api/function/raid_alldevices?params=storage_GetAllDisks')
        for adp in storagedata.get('items', []):
            for diskent in adp.get('disks', ()):
                yield self._get_disk_firmware_single(diskent)
            for diskent in adp.get('aimDisks', ()):
                yield self._get_disk_firmware_single(diskent)

    def get_firmware_inventory(self, components):
        sysinf = self.wc.grab_json_response('/api/dataset/sys_info')
        for item in sysinf.get('items', {}):
            for firm in item.get('firmware', []):
                firminfo = {
                    'version': firm['version'],
                    'build': firm['build'],
                    'date': parse_time(firm['release_date']),
                }
                if firm['type'] == 5:
                    yield ('XCC', firminfo)
                elif firm['type'] == 6:
                    yield ('XCC Backup', firminfo)
                elif firm['type'] == 0:
                    yield ('UEFI', firminfo)
                elif firm['type'] == 7:
                    yield ('LXPM', firminfo)
                elif firm['type'] == 8:
                    yield ('LXPM Windows Driver Bundle', firminfo)
                elif firm['type'] == 9:
                    yield ('LXPM Linux Driver Bundle', firminfo)
        for adpinfo in self._get_agentless_firmware(components):
            yield adpinfo
        for adpinfo in self._get_disk_firmware(components):
            yield adpinfo
        raise pygexc.BypassGenericBehavior()

    @property
    def wc(self):
        if (not self._wc or (self._wc.vintage and
                             self._wc.vintage < util._monotonic_time() - 30)):
            self._wc = self.get_webclient()
        return self._wc

    def get_webclient(self, login=True):
        wc = self.webclient.dupe()
        wc.vintage = util._monotonic_time()
        try:
            wc.connect()
        except socket.error as se:
            if se.errno != errno.ECONNREFUSED:
                raise
            return None
        if not login:
            return wc
        adata = json.dumps({'username': self.username,
                            'password': self.password
                            })
        headers = {'Connection': 'keep-alive',
                   'Content-Type': 'application/json'}
        wc.request('POST', '/api/login', adata, headers)
        rsp = wc.getresponse()
        if rsp.status == 200:
            rspdata = json.loads(rsp.read())
            wc.set_header('Content-Type', 'application/json')
            wc.set_header('Authorization', 'Bearer ' + rspdata['access_token'])
            if '_csrf_token' in wc.cookies:
                wc.set_header('X-XSRF-TOKEN', wc.cookies['_csrf_token'])
            return wc
