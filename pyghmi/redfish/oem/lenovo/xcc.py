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
import time
import pyghmi.ipmi.private.util as util
import pyghmi.exceptions as pygexc
import pyghmi.storage as storage


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

    def get_storage_configuration(self, logout=True):
        rsp = self.wc.grab_json_response(
            '/api/function/raid_alldevices?params=storage_GetAllDevices')
        standalonedisks = []
        pools = []
        for item in rsp.get('items', []):
            for cinfo in item['controllerInfo']:
                cid = cinfo['id']
                for pool in cinfo['pools']:
                    volumes = []
                    disks = []
                    spares = []
                    for volume in pool['volumes']:
                        volumes.append(
                            storage.Volume(name=volume['name'],
                                           size=volume['capacity'],
                                           status=volume['statusStr'],
                                           id=(cid, volume['id'])))
                    for disk in pool['disks']:
                        diskinfo = storage.Disk(
                            name=disk['name'], description=disk['type'],
                            id=(cid, disk['id']), status=disk['RAIDState'],
                            serial=disk['serialNo'], fru=disk['fruPartNo'])
                        if disk['RAIDState'] == 'Dedicated Hot Spare':
                            spares.append(diskinfo)
                        else:
                            disks.append(diskinfo)
                    totalsize = pool['totalCapacityStr'].replace('GB', '')
                    totalsize = int(float(totalsize) * 1024)
                    freesize = pool['freeCapacityStr'].replace('GB', '')
                    freesize = int(float(freesize) * 1024)
                    pools.append(storage.Array(
                        disks=disks, raid=pool['rdlvlstr'], volumes=volumes,
                        id=(cid, pool['id']), hotspares=spares,
                        capacity=totalsize, available_capacity=freesize))
                for disk in cinfo.get('unconfiguredDisks', ()):
                    # can be unused, global hot spare, or JBOD
                    standalonedisks.append(
                        storage.Disk(
                            name=disk['name'], description=disk['type'],
                            id=(cid, disk['id']), status=disk['RAIDState'],
                            serial=disk['serialNo'], fru=disk['fruPartNo']))
        return storage.ConfigSpec(disks=standalonedisks, arrays=pools)

    def _set_drive_state(self, disk, state):
        rsp = self.wc.grab_json_response(
            '/api/function',
            {'raidlink_DiskStateAction': '{0},{1}'.format(disk.id[1], state)})
        if rsp.get('return', -1) != 0:
            raise Exception(
                'Unexpected return to set disk state: {0}'.format(
                    rsp.get('return', -1)))

    def _make_available(self, disk, realcfg):
        # 8 if jbod, 4 if hotspare.., leave alone if already...
        currstatus = self._get_status(disk, realcfg)
        newstate = None
        if currstatus == 'Unconfigured Good':
            return
        elif currstatus.lower() == 'global hot spare':
            newstate = 4
        elif currstatus.lower() == 'jbod':
            newstate = 8
        self._set_drive_state(disk, newstate)

    def _make_jbod(self, disk, realcfg):
        currstatus = self._get_status(disk, realcfg)
        if currstatus.lower() == 'jbod':
            return
        self._make_available(disk, realcfg)
        self._set_drive_state(disk, 16)

    def _make_global_hotspare(self, disk, realcfg):
        currstatus = self._get_status(disk, realcfg)
        if currstatus.lower() == 'global hot spare':
            return
        self._make_available(disk, realcfg)
        self._set_drive_state(disk, 1)

    def _get_status(self, disk, realcfg):
        for cfgdisk in realcfg.disks:
            if disk.id == cfgdisk.id:
                currstatus = cfgdisk.status
                break
        else:
            raise pygexc.InvalidParameterValue('Requested disk not found')
        return currstatus

    def _raid_number_map(self, controller):
        themap = {}
        rsp = self.wc.grab_json_response(
            '/api/function/raid_conf?'
            'params=raidlink_GetDisksToConf,{0}'.format(controller))
        for lvl in rsp['items'][0]['supported_raidlvl']:
            mapdata = (lvl['rdlvl'], lvl['maxSpan'])
            raidname = lvl['rdlvlstr'].replace(' ', '').lower()
            themap[raidname] = mapdata
            raidname = raidname.replace('raid', 'r')
            themap[raidname] = mapdata
            raidname = raidname.replace('r', '')
            themap[raidname] = mapdata
        return themap

    def _wait_storage_async(self):
        rsp = {'items': [{'status': 0}]}
        while rsp['items'][0]['status'] == 0:
            time.sleep(1)
            rsp = self.wc.grab_json_response(
                '/api/function/raid_conf?params=raidlink_QueryAsyncStatus')

    def _parse_array_spec(self, arrayspec):
        controller = None
        if arrayspec.disks:
            for disk in list(arrayspec.disks) + list(arrayspec.hotspares):
                if controller is None:
                    controller = disk.id[0]
                if controller != disk.id[0]:
                    raise pygexc.UnsupportedFunctionality(
                        'Cannot span arrays across controllers')
            raidmap = self._raid_number_map(controller)
            if not raidmap:
                raise pygexc.InvalidParameterValue(
                    'There are no available drives for a new array')
            requestedlevel = str(arrayspec.raid).lower()
            if requestedlevel not in raidmap:
                raise pygexc.InvalidParameterValue(
                    'Requested RAID "{0}" not available on this '
                    'system with currently available drives'.format(
                        requestedlevel))
            rdinfo = raidmap[str(arrayspec.raid).lower()]
            rdlvl = str(rdinfo[0])
            defspan = 1 if rdinfo[1] == 1 else 2
            spancount = defspan if arrayspec.spans is None else arrayspec.spans
            drivesperspan = str(len(arrayspec.disks) // int(spancount))
            hotspares = arrayspec.hotspares
            drives = arrayspec.disks
            if hotspares:
                hstr = '|'.join([str(x.id[1]) for x in hotspares]) + '|'
            else:
                hstr = ''
            drvstr = '|'.join([str(x.id[1]) for x in drives]) + '|'
            pth = '/api/function/raid_conf?params=raidlink_CheckConfisValid'
            args = [pth, controller, rdlvl, spancount, drivesperspan, drvstr,
                    hstr]
            url = ','.join([str(x) for x in args])
            rsp = self.wc.grab_json_response(url)
            if rsp['items'][0]['errcode'] == 16:
                raise pygexc.InvalidParameterValue('Incorrect number of disks')
            elif rsp['items'][0]['errcode'] != 0:
                raise pygexc.InvalidParameterValue(
                    'Invalid configuration: {0}'.format(
                        rsp['items'][0]['errcode']))
            return {
                'capacity': rsp['items'][0]['freeCapacity'],
                'controller': controller,
                'drives': drvstr,
                'hotspares': hstr,
                'raidlevel': rdlvl,
                'spans': spancount,
                'perspan': drivesperspan,
            }
        else:
            pass  # TODO: adding new volume to existing array would be here

    def _create_array(self, pool):
        params = self._parse_array_spec(pool)
        url = '/api/function/raid_conf?params=raidlink_GetDefaultVolProp'
        args = (url, params['controller'], 0, params['drives'])
        props = self.wc.grab_json_response(','.join([str(x) for x in args]))
        props = props['items'][0]
        volumes = pool.volumes
        remainingcap = params['capacity']
        nameappend = 1
        vols = []
        currvolnames = None
        currcfg = None
        for vol in volumes:
            if vol.name is None:
                # need to iterate while there exists a volume of that name
                if currvolnames is None:
                    currcfg = self.get_storage_configuration(False)
                    currvolnames = set([])
                    for pool in currcfg.arrays:
                        for volume in pool.volumes:
                            currvolnames.add(volume.name)
                name = props['name'] + '_{0}'.format(nameappend)
                nameappend += 1
                while name in currvolnames:
                    name = props['name'] + '_{0}'.format(nameappend)
                    nameappend += 1
            else:
                name = vol.name
            if vol.stripsize:
                stripsize = int(math.log(vol.stripsize * 2, 2))
            else:
                stripsize = props['stripsize']
            strsize = 'remainder' if vol.size is None else str(vol.size)
            if strsize in ('all', '100%'):
                volsize = params['capacity']
            elif strsize in ('remainder', 'rest'):
                volsize = remainingcap
            elif strsize.endswith('%'):
                volsize = int(params['capacity'] *
                              float(strsize.replace('%', '')) / 100.0)
            else:
                try:
                    volsize = int(strsize)
                except ValueError:
                    raise pygexc.InvalidParameterValue(
                        'Unrecognized size ' + strsize)
            remainingcap -= volsize
            if remainingcap < 0:
                raise pygexc.InvalidParameterValue(
                    'Requested sizes exceed available capacity')
            vols.append('{0};{1};{2};{3};{4};{5};{6};{7};{8};|'.format(
                name, volsize, stripsize, props['cpwb'], props['cpra'],
                props['cpio'], props['ap'], props['dcp'], props['initstate']))
        url = '/api/function'
        arglist = '{0},{1},{2},{3},{4},{5},'.format(
            params['controller'], params['raidlevel'], params['spans'],
            params['perspan'], params['drives'], params['hotspares'])
        arglist += ''.join(vols)
        parms = {'raidlink_AddNewVolWithNaAsync': arglist}
        rsp = self.wc.grab_json_response(url, parms)
        if rsp['return'] != 0:
            raise Exception(
                'Unexpected response to add volume command: ' + repr(rsp))
        self._wait_storage_async()

    def remove_storage_configuration(self, cfgspec):
        realcfg = self.get_storage_configuration(False)
        for pool in cfgspec.arrays:
            for volume in pool.volumes:
                vid = '{0},{1}'.format(volume.id[1], volume.id[0])
                rsp = self.wc.grab_json_response(
                    '/api/function', {'raidlink_RemoveVolumeAsync': vid})
                if rsp.get('return', -1) != 0:
                    raise Exception(
                        'Unexpected return to volume deletion: ' + repr(rsp))
                self._wait_storage_async()
        for disk in cfgspec.disks:
            self._make_available(disk, realcfg)

    def apply_storage_configuration(self, cfgspec):
        realcfg = self.get_storage_configuration(False)
        for disk in cfgspec.disks:
            if disk.status.lower() == 'jbod':
                self._make_jbod(disk, realcfg)
            elif disk.status.lower() == 'hotspare':
                self._make_global_hotspare(disk, realcfg)
            elif disk.status.lower() in ('unconfigured', 'available', 'ugood',
                                         'unconfigured good'):
                self._make_available(disk, realcfg)
        for pool in cfgspec.arrays:
            if pool.disks:
                self._create_array(pool)

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
