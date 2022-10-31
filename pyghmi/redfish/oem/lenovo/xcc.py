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


import errno
import json
import math
import os
import random
import re
import socket
import time

import six

import pyghmi.exceptions as pygexc
import pyghmi.ipmi.private.util as util
import pyghmi.ipmi.oem.lenovo.config as config
import pyghmi.media as media
import pyghmi.redfish.oem.generic as generic
import pyghmi.storage as storage
from pyghmi.util.parse import parse_time
import pyghmi.util.webclient as webclient

numregex = re.compile('([0-9]+)')
funtypes = {
    0: 'RAID Controller',
    1: 'Ethernet',
    2: 'Fibre Channel',
    3: 'Infiniband',
    4: 'GPU',
    10: 'NVMe Controller',
    12: 'Fabric Controller',
}

tls_ver = {
    1: 'TLS1.1',
    2: 'TLS1.2',
    3: 'TLS1.3'
}

sec_mode = {
    0: ('Compatible',
        'Maximum compatibility of cipher suites, without NIST compliance'),
    1: ('NIST',
        'Maximum compatibility within the constraints of being NIST '
        'compliant with perfect forward secrecy'),
    2: ('High', 'Support only modern and strong ciphers, NIST '
                'compliant with perfect forward security'),
}


def naturalize_string(key):
    """Analyzes string in a human way to enable natural sort

    :param key: string for the split
    :returns: A structure that can be consumed by 'sorted'
    """
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(numregex, key)]


def natural_sort(iterable):
    """Return a sort using natural sort if possible

    :param iterable:
    :return:
    """
    try:
        return sorted(iterable, key=naturalize_string)
    except TypeError:
        # The natural sort attempt failed, fallback to ascii sort
        return sorted(iterable)


class OEMHandler(generic.OEMHandler):
    logouturl = '/api/providers/logout'
    bmcname = 'XCC'
    ADP_URL = '/api/dataset/imm_adapters?params=pci_GetAdapters'
    ADP_NAME = 'adapterName'
    ADP_FUN = 'functions'
    ADP_FU_URL = '/api/function/adapter_update?params=pci_GetAdapterListAndFW'
    ADP_LABEL = 'connectorLabel'
    ADP_SLOTNO = 'slotNo'
    ADP_OOB = 'oobSupported'
    ADP_PARTNUM = 'vpd_partNo'
    ADP_SERIALNO = 'vpd_serialNo'
    ADP_VENID = 'generic_vendorId'
    ADP_SUBVENID = 'generic_subVendor'
    ADP_DEVID = 'generic_devId'
    ADP_SUBDEVID = 'generic_subDevId'
    ADP_FRU = 'vpd_cardSKU'
    BUSNO = 'generic_busNo'
    PORTS = 'network_pPorts'
    DEVNO = 'generic_devNo'

    def __init__(self, sysinfo, sysurl, webclient, cache, gpool=None):
        super(OEMHandler, self).__init__(sysinfo, sysurl, webclient, cache,
                                         gpool)
        self._wc = None
        self.weblogging = False
        self.updating = False
        self.datacache = {}
        self.fwc = None
        self.fwo = None

    def get_system_configuration(self, hideadvanced=True, fishclient=None,
                                 fetchimm=False):
        if not self.fwc:
            self.fwc = config.LenovoFirmwareConfig(self, useipmi=False)
        try:
            self.fwo = self.fwc.get_fw_options(fetchimm=fetchimm)
        except config.Unsupported:
            return super(OEMHandler, self).get_system_configuration(
                hideadvanced, fishclient)
        except Exception:
            raise Exception('%s failed to retrieve UEFI configuration'
                            % self.bmcname)
        self.fwovintage = util._monotonic_time()
        retcfg = {}
        for opt in self.fwo:
            if 'MegaRAIDConfigurationTool' in opt:
                # Suppress the Avago configuration to be consistent with
                # other tools.
                continue
            if (hideadvanced and self.fwo[opt]['lenovo_protect']
                    or self.fwo[opt]['hidden']):
                # Do not enumerate hidden settings
                continue
            retcfg[opt] = {}
            retcfg[opt]['value'] = self.fwo[opt]['current']
            retcfg[opt]['default'] = self.fwo[opt]['default']
            retcfg[opt]['help'] = self.fwo[opt]['help']
            retcfg[opt]['possible'] = self.fwo[opt]['possible']
            retcfg[opt]['sortid'] = self.fwo[opt]['sortid']
        return retcfg

    def set_system_configuration(self, changeset, fishclient):
        if not self.fwc:
            self.fwc = config.LenovoFirmwareConfig(self, useipmi=False)
        fetchimm = False
        if not self.fwo or util._monotonic_time() - self.fwovintage > 30:
            try:
                self.fwo = self.fwc.get_fw_options(fetchimm=fetchimm)
            except config.Unsupported:
                return super(OEMHandler, self).set_system_configuration(
                    changeset, fishclient)
            self.fwovintage = util._monotonic_time()
        for key in list(changeset):
            if key not in self.fwo:
                found = False
                for rkey in self.fwo:
                    if fnmatch.fnmatch(rkey.lower(), key.lower()):
                        changeset[rkey] = changeset[key]
                        found = True
                    elif self.fwo[rkey].get('alias', None) != rkey:
                        calias = self.fwo[rkey]['alias']
                        if fnmatch.fnmatch(calias.lower(), key.lower()):
                            changeset[rkey] = changeset[key]
                            found = True
                if not found and not fetchimm:
                    fetchimm = True
                    self.fwo = self.fwc.get_fw_options(fetchimm=fetchimm)
                    if key in self.fwo:
                        continue
                    else:
                        found = False
                        for rkey in self.fwo:
                            if fnmatch.fnmatch(rkey.lower(), key.lower()):
                                changeset[rkey] = changeset[key]
                                found = True
                            elif self.fwo[rkey].get('alias', None) != rkey:
                                calias = self.fwo[rkey]['alias']
                                if fnmatch.fnmatch(
                                        calias.lower(), key.lower()):
                                    changeset[rkey] = changeset[key]
                                    found = True
                if found:
                    del changeset[key]
                else:
                    raise pygexc.InvalidParameterValue(
                        '{0} not a known setting'.format(key))
        self.merge_changeset(changeset)
        if changeset:
            try:
                self.fwc.set_fw_options(self.fwo)
            finally:
                self.fwo = None
                self.fwovintage = 0

    def merge_changeset(self, changeset):
        for key in changeset:
            if isinstance(changeset[key], six.string_types):
                changeset[key] = {'value': changeset[key]}
            newvalue = changeset[key]['value']
            if self.fwo[key]['is_list'] and not isinstance(newvalue, list):
                if '=' in newvalue:
                    # ASU set a precedent of = delimited settings
                    # for now, honor that delimiter as well
                    newvalues = newvalue.split('=')
                else:
                    newvalues = newvalue.split(',')
            else:
                newvalues = [newvalue]
            newnewvalues = []
            for newvalue in newvalues:
                newv = re.sub(r'\s+', ' ', newvalue)
                if (self.fwo[key]['possible']
                        and newvalue not in self.fwo[key]['possible']):
                    candlist = []
                    for candidate in self.fwo[key]['possible']:
                        candid = re.sub(r'\s+', ' ', candidate)
                        if newv.lower().startswith(candid.lower()):
                            newvalue = candidate
                            break
                        if candid.lower().startswith(newv.lower()):
                            candlist.append(candidate)
                    else:
                        if len(candlist) == 1:
                            newvalue = candlist[0]
                        else:
                            raise pygexc.InvalidParameterValue(
                                '{0} is not a valid value for {1} '
                                '({2})'.format(
                                    newvalue, key,
                                    ','.join(self.fwo[key]['possible'])))
                newnewvalues.append(newvalue)
            if len(newnewvalues) == 1:
                self.fwo[key]['new_value'] = newnewvalues[0]
            else:
                self.fwo[key]['new_value'] = newnewvalues

    def reseat_bay(self, bay):
        if bay != -1:
            raise pygexc.UnsupportedFunctionality(
                'This is not an enclosure manager')
        rsp = self.wc.grab_json_response_with_status(
            '/api/providers/virt_reseat', '{}')
        if rsp[1] != 200 or rsp[0].get('return', 1) != 0:
            raise pygexc.UnsupportedFunctionality(
                'This platform does not support AC reseat.')

    def get_cached_data(self, attribute, age=30):
        try:
            kv = self.datacache[attribute]
            if kv[1] > util._monotonic_time() - age:
                return kv[0]
        except KeyError:
            return None

    def get_bmc_configuration(self):
        settings = {}
        passrules = self.wc.grab_json_response('/api/dataset/imm_users_global')
        passrules = passrules.get('items', [{}])[0]
        settings['password_reuse_count'] = {
            'value': passrules.get('pass_min_resuse')}
        settings['password_change_interval'] = {
            'value': passrules.get('pass_change_interval')}
        settings['password_expiration'] = {
            'value': passrules.get('pass_expire_days')}
        settings['password_login_failures'] = {
            'value': passrules.get('max_login_failures')}
        settings['password_complexity'] = {
            'value': passrules.get('pass_complex_required')}
        settings['password_min_length'] = {
            'value': passrules.get('pass_min_length')}
        settings['password_lockout_period'] = {
            'value': passrules.get('lockout_period')}
        presassert = self.wc.grab_json_response('/api/dataset/imm_rpp')
        asserted = presassert.get('items', [{}])[0].get('rpp_Assert', None)
        if asserted is not None:
            settings['presence_assert'] = {
                'value': 'Enable' if asserted else 'Disable'
            }
        secparms = self.wc.grab_json_response('/api/providers/imm_tls_mode')
        if secparms and secparms.get('return', 1) == 0:
            tlsmode = secparms.get('tls_ver', -1)
            if tlsmode in tls_ver:
                settings['minimum_tls_version'] = {
                    'value': tls_ver[tlsmode],
                    'help': 'The minimum TLS level allowed by the XCC when '
                            'communicating',
                    'possible': [tls_ver[x] for x in tls_ver],
                }
            secmode = secparms.get('sec_mode', -1)
            if secmode in sec_mode:
                settings['cryptography_mode'] = {
                    'value': sec_mode[secmode][0],
                    'help': 'Select cryptography mode, compatible allows all '
                            'supported ciphers, NIST restricts to NIST '
                            'compliant ciphers, and High further restricts '
                            'to a modern subset of NIST compliance',
                    'possible': [sec_mode[x][0] for x in sec_mode],
                }
        usbparms = self.wc.grab_json_response('/api/dataset/imm_usb')
        if usbparms:
            usbparms = usbparms.get('items', [{}])[0]
            if usbparms['usb_eth_over_usb_enabled'] == 1:
                usbeth = 'Enable'
            else:
                usbeth = 'Disable'
            settings['usb_ethernet'] = {
                'value': usbeth
            }
            if usbparms['usb_eth_to_eth_enabled'] == 1:
                fwd = 'Enable'
            else:
                fwd = 'Disable'
            settings['usb_ethernet_port_forwarding'] = {
                'value': fwd
            }
            mappings = []
            for mapping in usbparms['usb_mapped_ports']:
                src = mapping['ext_port']
                dst = mapping['eth_port']
                if src != 0 and dst != 0:
                    mappings.append('{0}:{1}'.format(src, dst))
            settings['usb_forwarded_ports'] = {'value': ','.join(mappings)}
        return settings

    rulemap = {
        'password_change_interval': 'USER_GlobalMinPassChgInt',
        'password_reuse_count': 'USER_GlobalMinPassReuseCycle',
        'password_expiration': 'USER_GlobalPassExpPeriod',
        'password_login_failures': 'USER_GlobalMaxLoginFailures',
        'password_complexity': 'USER_GlobalPassComplexRequired',
        'password_min_length': 'USER_GlobalMinPassLen',
        'password_lockout_period': 'USER_GlobalLockoutPeriod',
    }

    def set_bmc_configuration(self, changeset):
        ruleset = {}
        usbsettings = {}
        secparms = {}
        for key in changeset:
            if isinstance(changeset[key], six.string_types):
                changeset[key] = {'value': changeset[key]}
            currval = changeset[key].get('value', None)
            if key.lower() in self.rulemap:
                ruleset[self.rulemap[key.lower()]] = currval
                if key.lower() == 'password_expiration':
                    warntime = str(int(int(currval) * 0.08))
                    ruleset['USER_GlobalPassExpWarningPeriod'] = warntime
            elif 'presence_asserted'.startswith(key.lower()):
                if 'enabled'.startswith(currval.lower()):
                    self.wc.grab_json_response('/api/dataset',
                                               {'IMM_RPPAssert': '0'})
                    self.wc.grab_json_response('/api/dataset',
                                               {'IMM_RPPAssert': '1'})
                elif 'disabled'.startswith(currval.lower()):
                    self.wc.grab_json_response('/api/dataset',
                                               {'IMM_RPPAssert': '0'})
                else:
                    raise pygexc.InvalidParameterValue(
                        '"{0}" is not a recognized value for {1}'.format(
                            currval, key))
            elif key.lower() in (
                    'usb_ethernet', 'usb_ethernet_port_forwarding',
                    'usb_forwarded_ports'):
                usbsettings[key] = changeset[key]['value']
            elif key.lower() in ('cryptography_mode', 'minimum_tls_version'):
                secparms[key] = changeset[key]['value']
            else:
                raise pygexc.InvalidParameterValue(
                    '{0} not a known setting'.format(key))
        if usbsettings:
            self.apply_usb_configuration(usbsettings)
        if secparms:
            self.apply_sec_configuration(secparms)
        if ruleset:
            self.wc.grab_json_response('/api/dataset', ruleset)

    def apply_sec_configuration(self, secparms):
        secmode = None
        tlsver = None
        if 'cryptography_mode' in secparms:
            secmode = secparms['cryptography_mode'].lower()
            for sm in sec_mode:
                if sec_mode[sm][0].lower().startswith(secmode):
                    secmode = sm
                    break
            else:
                raise pygexc.InvalidParameterValue(
                    '"{0}" is not a recognized cryptography mode'.format(
                        secparms['cryptography_mode']
                    )
                )
        if 'minimum_tls_version' in secparms:
            tlsver = secparms['minimum_tls_version'].lower()
            for tv in tls_ver:
                if tls_ver[tv].lower() == tlsver:
                    tlsver = tv
                    break
            else:
                raise pygexc.InvalidParameterValue(
                    '"{0}" is not a recognized TLS version'.format(
                        secparms['minimum_tls_version'])
                )
        if len(secparms) < 2:
            currsecparms = self.wc.grab_json_response(
                '/api/providers/imm_tls_mode')
            del currsecparms['return']
        else:
            currsecparms = {}
        if secmode is not None:
            currsecparms['sec_mode'] = secmode
        if tlsver is not None:
            currsecparms['tls_ver'] = tlsver
        self.wc.grab_json_response('/api/providers/imm_tls_mode',
                                   currsecparms)

    def apply_usb_configuration(self, usbsettings):
        def numify(val):
            if 'enabled'.startswith(val.lower()):
                return '1'
            if 'disabled'.startswith(val.lower()):
                return '0'
            raise Exception('Usupported value')
        usbparms = self.wc.grab_json_response('/api/dataset/imm_usb')
        usbparms = usbparms.get('items', [{}])[0]
        addrmode = '{0}'.format(usbparms['lan_over_usb_addr_mode'])
        ethena = '{0}'.format(usbparms['usb_eth_over_usb_enabled'])
        fwdena = '{0}'.format(usbparms['usb_eth_to_eth_enabled'])
        newena = usbsettings.get('usb_ethernet', None)
        newfwd = usbsettings.get('usb_ethernet_port_forwarding', None)
        newsettings = {
            'USB_LANOverUSBAddrMode': addrmode,
            'USB_EthOverUsbEna': ethena,
            'USB_PortForwardEna': fwdena,
            'USB_IPChangeEna': '0',
        }
        needsettings = False
        if newena is not None:
            needsettings = True
            newsettings['USB_EthOverUsbEna'] = numify(newena)
        if newfwd is not None:
            needsettings = True
            newsettings['USB_PortForwardEna'] = numify(newfwd)
        if needsettings:
            self.wc.grab_json_response('/api/dataset', newsettings)
        if 'usb_forwarded_ports' in usbsettings:
            oldfwds = {}
            usedids = set([])
            newfwds = usbsettings['usb_forwarded_ports'].split(',')
            for mapping in usbparms['usb_mapped_ports']:
                rule = '{0}:{1}'.format(
                    mapping['ext_port'], mapping['eth_port'])
                if rule not in newfwds:
                    self.wc.grab_json_response(
                        '/api/function', {
                            'USB_RemoveMapping': '{0}'.format(mapping['id'])})
                else:
                    usedids.add(mapping['id'])
                    oldfwds[rule] = mapping['id']
            for mapping in usbsettings['usb_forwarded_ports'].split(','):
                if mapping not in oldfwds:
                    newid = 1
                    while newid in usedids:
                        newid += 1
                    if newid > 11:
                        raise Exception('Too Many Port Forwards')
                    usedids.add(newid)
                    newmapping = '{0},{1}'.format(
                        newid, mapping.replace(':', ','))
                    self.wc.grab_json_response(
                        '/api/function', {'USB_AddMapping': newmapping})

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
        adata = self.wc.grab_json_response(
            '/api/dataset/imm_adapters?params=pci_GetAdapters')
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
                    if ('releaseDate' in firm
                            and firm['releaseDate']
                            and firm['releaseDate'] != 'N/A'):
                        try:
                            bdata['date'] = parse_time(firm['releaseDate'])
                        except ValueError:
                            pass
                    yield '{0} {1}'.format(aname, fname), bdata

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
            '/api/function/raid_alldevices?params=storage_GetAllDevices,0')
        if not rsp:
            rsp = self.wc.grab_json_response(
                '/api/function/raid_alldevices?params=storage_GetAllDevices')
        standalonedisks = []
        pools = []
        for item in rsp.get('items', []):
            for cinfo in item['controllerInfo']:
                cid = '{0},{1},{2}'.format(
                    cinfo['id'], cinfo.get('slotNo', -1), cinfo.get(
                        'type', -1))
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
                    totalsize = pool['totalCapacityStr'].replace(
                        'GB', '').replace('GiB', '')
                    totalsize = int(float(totalsize) * 1024)
                    freesize = pool['freeCapacityStr'].replace(
                        'GB', '').replace('GiB', '')
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

    def _refresh_token(self):
        self._refresh_token_wc(self.wc)

    def _refresh_token_wc(self, wc):
        wc.grab_json_response('/api/providers/identity')
        if '_csrf_token' in wc.cookies:
            wc.set_header('X-XSRF-TOKEN', self.wc.cookies['_csrf_token'])
            wc.vintage = util._monotonic_time()

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
        cid = controller.split(',')
        rsp = self.wc.grab_json_response(
            '/api/function/raid_conf?'
            'params=raidlink_GetDisksToConf,{0}'.format(cid[0]))
        if rsp.get('return') == 22:  # New style firmware
            if cid[2] == 2:
                arg = '{0},{1}'.format(cid[1], cid[2])
            else:
                arg = '{0},{1}'.format(cid[0], cid[2])
            arg = 'params=raidlink_GetDisksToConf,{0}'.format(arg)
            rsp = self.wc.grab_json_response(
                '/api/function/raid_conf?{0}'.format(arg))
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
            ctl = controller.split(',')
            pth = '/api/function/raid_conf?params=raidlink_CheckConfisValid'
            args = [pth, ctl[0], rdlvl, spancount, drivesperspan, drvstr,
                    hstr]
            url = ','.join([str(x) for x in args])
            rsp = self.wc.grab_json_response(url)
            if rsp.get('return', -1) == 22:
                args.append(ctl[1])
                args = [pth, ctl[0], rdlvl, spancount, drivesperspan, drvstr,
                        hstr, ctl[1]]
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
            # TODO(Jarrod Johnson): adding new volume to
            #  existing array would be here
            pass

    def _create_array(self, pool):
        params = self._parse_array_spec(pool)
        cid = params['controller'].split(',')[0]
        url = '/api/function/raid_conf?params=raidlink_GetDefaultVolProp'
        args = (url, cid, 0, params['drives'])
        props = self.wc.grab_json_response(','.join([str(x) for x in args]))
        if not props:  # newer firmwarerequires raidlevel too
            args = (url, cid, params['raidlevel'], 0, params['drives'])
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
            if vol.stripsize is not None:
                stripsize = int(math.log(vol.stripsize * 2, 2))
            else:
                stripsize = props['stripsize']
            if vol.read_policy is not None:
                read_policy = vol.read_policy
            else:
                read_policy = props["cpra"]
            if vol.write_policy is not None:
                write_policy = vol.write_policy
            else:
                write_policy = props["cpwb"]
            if vol.default_init is not None:
                default_init = vol.default_init
            else:
                default_init = props["initstate"]
            strsize = 'remainder' if vol.size is None else str(vol.size)
            if strsize in ('all', '100%'):
                volsize = params['capacity']
            elif strsize in ('remainder', 'rest'):
                volsize = remainingcap
            elif strsize.endswith('%'):
                volsize = int(params['capacity']
                              * float(strsize.replace('%', ''))
                              / 100.0)
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
                name, volsize, stripsize, write_policy, read_policy,
                props['cpio'], props['ap'], props['dcp'], default_init))
        url = '/api/function'
        cid = params['controller'].split(',')
        cnum = cid[0]
        arglist = '{0},{1},{2},{3},{4},{5},'.format(
            cnum, params['raidlevel'], params['spans'],
            params['perspan'], params['drives'], params['hotspares'])
        arglist += ''.join(vols)
        parms = {'raidlink_AddNewVolWithNaAsync': arglist}
        rsp = self.wc.grab_json_response(url, parms)
        if rsp['return'] == 14:  # newer firmware
            if 'supported_cpwb' in props: # Whitley
                arglist = '{0},{1},{2},{3},{4},{5},{6},'.format(
                    cnum, params['raidlevel'], params['spans'],
                    params['perspan'], 0, params['drives'], params['hotspares'])
                arglist += ''.join(vols)
                parms = {'raidlink_AddNewVolWithNaAsync': arglist}
                rsp = self.wc.grab_json_response(url, parms)
            else: # Purley
                if cid[2] == 2:
                    cnum = cid[1]
                arglist = '{0},{1},{2},{3},{4},{5},'.format(
                    cnum, params['raidlevel'], params['spans'],
                    params['perspan'], params['drives'], params['hotspares'])
                arglist += ''.join(vols) + ',{0}'.format(cid[2])
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
                cid = volume.id[0].split(',')
                if cid[2] == 2:
                    vid = '{0},{1},{2}'.format(volume.id[1], cid[1], cid[2])
                else:
                    vid = '{0},{1},{2}'.format(volume.id[1], cid[0], cid[2])
                rsp = self.wc.grab_json_response(
                    '/api/function', {'raidlink_RemoveVolumeAsync': vid})
                if rsp.get('return', -1) == 2:
                    # older firmware
                    vid = '{0},{1}'.format(volume.id[1], cid[0])
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

    def weblogout(self):
        if self._wc:
            try:
                self._wc.grab_json_response(self.logouturl)
            except Exception:
                pass
            self._wc = None

    @property
    def wc(self):
        while self.weblogging:
            time.sleep(0.25)
        self.weblogging = True
        try:
            if (not self._wc or (self._wc.vintage
                                and self._wc.vintage < util._monotonic_time()
                                - 30)):
                if not self.updating and self._wc:
                    # in case the existing session is still valid
                    # dispose of the session
                    self.weblogout()
                self._wc = self.get_webclient()
        finally:
            self.weblogging = False
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
        referer = 'https://xcc/'
        adata = json.dumps({'username': self.username,
                            'password': self.password
                            })
        headers = {'Connection': 'keep-alive',
                   'Referer': referer,
                   'Host': 'xcc',
                   'Content-Type': 'application/json'}
        rsp, status = wc.grab_json_response_with_status(
            '/api/providers/get_nonce', {})
        if status == 200:
            nonce = rsp.get('nonce', None)
            headers['Content-Security-Policy'] = 'nonce={0}'.format(nonce)
        wc.request('POST', '/api/login', adata, headers)
        rsp = wc.getresponse()
        if rsp.status == 200:
            rspdata = json.loads(rsp.read())
            wc.set_header('Content-Type', 'application/json')
            wc.set_header('Authorization', 'Bearer ' + rspdata['access_token'])
            wc.set_header('Referer', referer)
            wc.set_header('Host', 'xcc')
            if '_csrf_token' in wc.cookies:
                wc.set_header('X-XSRF-TOKEN', wc.cookies['_csrf_token'])
            return wc

    def grab_redfish_response_with_status(self, url, body=None, method=None):
        wc = self.webclient.dupe()
        res = wc.grab_json_response_with_status(url, body, method=method)
        return res

    def list_media(self, fishclient):
        rt = self.wc.grab_json_response('/api/providers/rp_vm_remote_getdisk')
        if 'items' in rt:
            for mt in rt['items']:
                url = mt['remotepath']
                if url.startswith('//'):
                    url = 'smb:' + url
                elif (not url.startswith('http://')
                      and not url.startswith('https://')):
                    url = url.replace(':', '')
                    url = 'nfs://' + url
                yield media.Media(mt['filename'], url)
        rt = self.wc.grab_json_response('/api/providers/rp_rdoc_imagelist')
        if 'items' in rt:
            for mt in rt['items']:
                yield media.Media(mt['filename'])

    def attach_remote_media(self, url, user, password, vmurls):
        for vmurl in vmurls:
            if 'EXT' not in vmurl:
                continue
            vminfo = self._do_web_request(vmurl, cache=False)
            if vminfo['ConnectedVia'] != 'NotConnected':
                continue
            self._do_web_request(vmurl, {'Image': url, 'Inserted': True},
                                 'PATCH')
            raise pygexc.BypassGenericBehavior()
            break
        else:
            raise pygexc.InvalidParameterValue(
                'XCC does not have required license for operation')

    def upload_media(self, filename, progress=None, data=None):
        wc = self.wc
        self._refresh_token()
        rsp, statu = wc.grab_json_response_with_status('/rdocupload')
        newmode = False
        if statu == 404:
            xid = random.randint(0, 1000000000)
            uploadthread = webclient.FileUploader(
                wc, '/upload?X-Progress-ID={0}'.format(xid), filename, data)
        else:
            newmode = True
            uploadthread = webclient.FileUploader(
                wc, '/rdocupload', filename, data)
        uploadthread.start()
        while uploadthread.isAlive():
            uploadthread.join(3)
            if newmode:
                if progress:
                    progress({'phase': 'upload',
                          'progress': 100 * wc.get_upload_progress()})
            else:
                rsp = self.wc.grab_json_response(
                    '/upload/progress?X-Progress-ID={0}'.format(xid))
                if progress and rsp['state'] == 'uploading':
                    progress({'phase': 'upload',
                            'progress': 100.0 * rsp['received'] / rsp['size']})
            self._refresh_token()
        rsp = json.loads(uploadthread.rsp)
        if progress:
            progress({'phase': 'upload',
                      'progress': 100.0})
        thepath = rsp['items'][0]['path']
        thename = rsp['items'][0]['name']
        writeable = 1 if filename.lower().endswith('.img') else 0
        addfile = {"Url": thepath, "Protocol": 6, "Write": writeable,
                   "Credential": ":", "Option": "", "Domain": "",
                   "WebUploadName": thename}
        rsp = self.wc.grab_json_response('/api/providers/rp_rdoc_addfile',
                                         addfile)
        self._refresh_token()
        if rsp.get('return', -1) != 0:
            errmsg = repr(rsp) if rsp else self.wc.lastjsonerror
            raise Exception('Unrecognized return: ' + errmsg)
        ready = False
        while not ready:
            time.sleep(3)
            rsp = self.wc.grab_json_response('/api/providers/rp_rdoc_getfiles')
            if 'items' not in rsp or len(rsp['items']) == 0:
                raise Exception(
                    'Image upload was not accepted, it may be too large')
            ready = rsp['items'][0]['size'] != 0
        self._refresh_token()
        rsp = self.wc.grab_json_response('/api/providers/rp_rdoc_mountall',
                                         {})
        self._refresh_token()
        if rsp.get('return', -1) != 0:
            errmsg = repr(rsp) if rsp else self.wc.lastjsonerror
            raise Exception('Unrecognized return: ' + errmsg)
        if progress:
            progress({'phase': 'complete'})

    def redfish_update_firmware(self, usd, filename, data, progress, bank):
        if usd['HttpPushUriTargetsBusy']:
            raise pygexc.TemporaryError('Cannot run multtiple updates to '
                                        'same target concurrently')
        upurl = usd['HttpPushUri']
        self._do_web_request(
            '/redfish/v1/UpdateService',
            {'HttpPushUriTargetsBusy': True}, method='PATCH')
        try:
            if bank == 'backup':
                self._do_web_request(
                    '/redfish/v1/UpdateService',
                    {'HttpPushUriTargets':
                        ['/redfish/v1/UpdateService'
                         '/FirmwareInventory/BMC-Backup']}, method='PATCH')
            uploadthread = webclient.FileUploader(
                self.webclient, upurl, filename, data, formwrap=False,
                excepterror=False)
            uploadthread.start()
            wc = self.webclient
            while uploadthread.isAlive():
                uploadthread.join(3)
                if progress:
                    progress(
                        {'phase': 'upload',
                         'progress': 100 * wc.get_upload_progress()})
            if (uploadthread.rspstatus >= 300
                    or uploadthread.rspstatus < 200):
                rsp = uploadthread.rsp
                errmsg = ''
                try:
                    rsp = json.loads(rsp)
                    errmsg = (
                        rsp['error'][
                            '@Message.ExtendedInfo'][0]['Message'])
                except Exception:
                    raise Exception(uploadthread.rsp)
                raise Exception(errmsg)
            rsp = json.loads(uploadthread.rsp)
            monitorurl = rsp['TaskMonitor']
            complete = False
            while not complete:
                pgress = self._do_web_request(monitorurl, cache=False)
                if not pgress:
                    break
                for msg in pgress.get('Messages', []):
                    if 'Verify failed' in msg.get('Message', ''):
                        raise Exception(msg['Message'])
                state = pgress['TaskState']
                if state in ('Cancelled', 'Exception', 'Interrupted',
                             'Suspended'):
                    raise Exception(
                        json.dumps(json.dumps(pgress['Messages'])))
                pct = float(pgress['PercentComplete'])
                complete = state == 'Completed'
                progress({'phase': 'apply', 'progress': pct})
                if not complete:
                    time.sleep(3)
            if bank == 'backup':
                return 'complete'
            return 'pending'
        finally:
            self._do_web_request(
                '/redfish/v1/UpdateService',
                {'HttpPushUriTargetsBusy': False}, method='PATCH')
            self._do_web_request(
                '/redfish/v1/UpdateService',
                {'HttpPushUriTargets': []}, method='PATCH')

    def update_firmware(self, filename, data=None, progress=None, bank=None):
        result = None
        usd = self._do_web_request('/redfish/v1/UpdateService')
        rfishurl = usd.get('HttpPushUri', None)
        if rfishurl:
            return self.redfish_update_firmware(
                usd, filename, data, progress, bank)
        if self.updating:
            raise pygexc.TemporaryError('Cannot run multiple updates to same '
                                        'target concurrently')
        self.updating = True
        try:
            result = self.update_firmware_backend(filename, data, progress,
                                                  bank)
        except Exception:
            self.updating = False
            self._refresh_token()
            self.wc.grab_json_response('/api/providers/fwupdate', json.dumps(
                {'UPD_WebCancel': 1}))
            raise
        self.updating = False
        return result

    def update_firmware_backend(self, filename, data=None, progress=None,
                                bank=None):
        self._refresh_token()
        rsv = self.wc.grab_json_response('/api/providers/fwupdate', json.dumps(
            {'UPD_WebReserve': 1}))
        if rsv['return'] == 103:
            raise Exception('Update already in progress')
        if rsv['return'] != 0:
            raise Exception('Unexpected return to reservation: ' + repr(rsv))
        xid = random.randint(0, 1000000000)
        uploadthread = webclient.FileUploader(
            self.wc, '/upload?X-Progress-ID={0}'.format(xid), filename, data)
        uploadthread.start()
        uploadstate = None
        while uploadthread.isAlive():
            uploadthread.join(3)
            rsp = self.wc.grab_json_response(
                '/upload/progress?X-Progress-ID={0}'.format(xid))
            if rsp['state'] == 'uploading':
                progress({'phase': 'upload',
                          'progress': 100.0 * rsp['received'] / rsp['size']})
            elif rsp['state'] != 'done':
                if (rsp.get('status', None) == 413
                        or uploadthread.rspstatus == 413):
                    raise Exception('File is larger than supported')
                raise Exception('Unexpected result:' + repr(rsp))
            uploadstate = rsp['state']
            self._refresh_token()
        while uploadstate != 'done':
            rsp = self.wc.grab_json_response(
                '/upload/progress?X-Progress-ID={0}'.format(xid))
            uploadstate = rsp['state']
            self._refresh_token()
        rsp = json.loads(uploadthread.rsp)
        if rsp['items'][0]['name'] != os.path.basename(filename):
            raise Exception('Unexpected response: ' + repr(rsp))
        progress({'phase': 'validating',
                  'progress': 0.0})
        time.sleep(3)
        # aggressive timing can cause the next call to occasionally
        # return 25 and fail
        self._refresh_token()
        rsp = self.wc.grab_json_response('/api/providers/fwupdate', json.dumps(
            {'UPD_WebSetFileName': rsp['items'][0]['path']}))
        if rsp.get('return', 0) in (25, 108):
            raise Exception('Temporary error validating update, try again')
        if rsp.get('return', -1) != 0:
            errmsg = repr(rsp) if rsp else self.wc.lastjsonerror
            raise Exception('Unexpected return to set filename: ' + errmsg)
        self._refresh_token()
        progress({'phase': 'validating',
                  'progress': 25.0})
        rsp = self.wc.grab_json_response('/api/providers/fwupdate', json.dumps(
            {'UPD_WebVerifyUploadFile': 1}))
        if rsp.get('return', 0) == 115:
            raise Exception('Update image not intended for this system')
        elif rsp.get('return', -1) == 108:
            raise Exception('Temporary error validating update, try again')
        elif rsp.get('return', -1) == 109:
            raise Exception('Invalid update file or component '
                            'does not support remote update')
        elif rsp.get('return', -1) != 0:
            errmsg = repr(rsp) if rsp else self.wc.lastjsonerror
            raise Exception('Unexpected return to verify: ' + errmsg)
        verifystatus = 0
        verifyuploadfilersp = None
        while verifystatus != 1:
            self._refresh_token()
            rsp, status = self.wc.grab_json_response_with_status(
                '/api/providers/fwupdate',
                json.dumps({'UPD_WebVerifyUploadFileStatus': 1}))
            if not rsp or status != 200 or rsp.get('return', -1) == 2:
                # The XCC firmware predates the FileStatus api
                verifyuploadfilersp = rsp
                break
            if rsp.get('return', -1) == 109:
                raise Exception('Invalid update file or component '
                                'does not support remote update')
            if rsp.get('return', -1) != 0:
                errmsg = repr(rsp) if rsp else self.wc.lastjsonerror
                raise Exception(
                    'Unexpected return to verifystate: {0}'.format(errmsg))
            verifystatus = rsp['status']
            if verifystatus == 2:
                raise Exception('Failed to verify firmware image')
            if verifystatus != 1:
                time.sleep(1)
            if verifystatus not in (0, 1, 255):
                errmsg = repr(rsp) if rsp else self.wc.lastjsonerror
                raise Exception(
                    'Unexpected reply to verifystate: ' + errmsg)
        progress({'phase': 'validating',
                  'progress': 99.0})
        self._refresh_token()
        rsp = self.wc.grab_json_response('/api/dataset/imm_firmware_success')
        if len(rsp['items']) != 1:
            raise Exception('Unexpected result: ' + repr(rsp))
        firmtype = rsp['items'][0]['firmware_type']
        if not firmtype:
            raise Exception('Unknown firmware description returned: ' + repr(
                rsp['items'][0]) + ' last verify return was: ' + repr(
                    verifyuploadfilersp) + ' with code {0}'.format(status))
        if firmtype not in (
                'TDM', 'WINDOWS DRIV', 'LINUX DRIVER', 'UEFI', 'IMM'):
            # adapter firmware
            webid = rsp['items'][0]['webfile_build_id']
            locations = webid[webid.find('[') + 1:webid.find(']')]
            locations = locations.split(':')
            validselectors = set([])
            for loc in locations:
                validselectors.add(loc.replace('#', '-'))
            self._refresh_token()
            rsp = self.wc.grab_json_response(
                '/api/function/adapter_update?params=pci_GetAdapterListAndFW')
            foundselectors = []
            for adpitem in rsp['items']:
                selector = '{0}-{1}'.format(adpitem['location'],
                                            adpitem['slotNo'])
                if selector in validselectors:
                    foundselectors.append(selector)
                    if len(foundselectors) == len(validselectors):
                        break
            else:
                raise Exception('Could not find matching adapter for update')
            self._refresh_token()
            rsp = self.wc.grab_json_response('/api/function', json.dumps(
                {'pci_SetOOBFWSlots': '|'.join(foundselectors)}))
            if rsp.get('return', -1) != 0:
                errmsg = repr(rsp) if rsp else self.wc.lastjsonerror
                raise Exception(
                    'Unexpected result from PCI select: ' + errmsg)
        else:
            self._refresh_token()
            rsp = self.wc.grab_json_response(
                '/api/dataset/imm_firmware_update')
            if rsp['items'][0]['upgrades'][0]['id'] != 1:
                raise Exception('Unexpected answer: ' + repr(rsp))
        self._refresh_token()
        progress({'phase': 'apply',
                  'progress': 0.0})
        if bank in ('primary', None):
            rsp = self.wc.grab_json_response(
                '/api/providers/fwupdate', json.dumps(
                    {'UPD_WebStartDefaultAction': 1}))
        elif bank == 'backup':
            rsp = self.wc.grab_json_response(
                '/api/providers/fwupdate', json.dumps(
                    {'UPD_WebStartOptionalAction': 2}))

        if rsp.get('return', -1) != 0:
            errmsg = repr(rsp) if rsp else self.wc.lastjsonerror
            raise Exception('Unexpected result starting update: %s' % errmsg)
        complete = False
        while not complete:
            self._refresh_token()
            time.sleep(3)
            rsp = self.wc.grab_json_response(
                '/api/dataset/imm_firmware_progress')
            progress({'phase': 'apply',
                      'progress': rsp['items'][0]['action_percent_complete']})
            if rsp['items'][0]['action_state'] == 'Idle':
                complete = True
                break
            if rsp['items'][0]['action_state'] == 'Complete OK':
                complete = True
                if rsp['items'][0]['action_status'] != 0:
                    raise Exception('Unexpected failure: %s' % repr(rsp))
                break
            if (rsp['items'][0]['action_state'] == 'In Progress'
                    and rsp['items'][0]['action_status'] == 2):
                raise Exception('Unexpected failure: ' + repr(rsp))
            if rsp['items'][0]['action_state'] != 'In Progress':
                raise Exception(
                    'Unknown condition waiting for '
                    'firmware update: %s' % repr(rsp))
        if bank == 'backup':
            return 'complete'
        return 'pending'

    def get_diagnostic_data(self, savefile, progress=None, autosuffix=False):
        self.wc.grab_json_response('/api/providers/ffdc',
                                   {'Generate_FFDC': 1})
        percent = 0
        while percent != 100:
            time.sleep(3)
            result = self.wc.grab_json_response('/api/providers/ffdc',
                                                {'Generate_FFDC_status': 1})
            self._refresh_token()
            if progress:
                progress({'phase': 'initializing', 'progress': float(percent)})
            percent = result['progress']
        while 'FileName' not in result:
            result = self.wc.grab_json_response('/api/providers/ffdc',
                                                {'Generate_FFDC_status': 1})
        url = '/ffdc/{0}'.format(result['FileName'])
        if autosuffix and not savefile.endswith('.tzz'):
            savefile += '-{0}'.format(result['FileName'])
        fd = webclient.FileDownloader(self.wc, url, savefile)
        fd.start()
        while fd.isAlive():
            fd.join(1)
            if progress and self.wc.get_download_progress():
                progress({'phase': 'download',
                          'progress': 100 * self.wc.get_download_progress()})
            self._refresh_token()
        if fd.exc:
            raise fd.exc
        if progress:
            progress({'phase': 'complete'})
        return savefile

    def get_licenses(self):
        licdata = self.wc.grab_json_response('/api/providers/imm_fod')
        for lic in licdata.get('items', [{}])[0].get('keys', []):
            if lic['status'] == 0:
                yield {'name': lic['feature'], 'state': 'Active'}
            if lic['status'] == 10:
                yield {
                    'name': lic['feature'],
                    'state': 'Missing required license'
                }

    def delete_license(self, name):
        licdata = self.wc.grab_json_response('/api/providers/imm_fod')
        for lic in licdata.get('items', [{}])[0].get('keys', []):
            if lic.get('feature', None) == name:
                licid = ','.join((str(lic['type']), str(lic['id'])))
                self.wc.grab_json_response(
                    '/api/providers/imm_fod',
                    {
                        'FOD_LicenseKeyDelete': licid
                    }
                )
                break

    def save_licenses(self, directory):
        licdata = self.wc.grab_json_response('/api/providers/imm_fod')
        for lic in licdata.get('items', [{}])[0].get('keys', []):
            licid = ','.join((str(lic['type']), str(lic['id'])))
            rsp = self.wc.grab_json_response(
                '/api/providers/imm_fod', {'FOD_LicenseKeyExport': licid})
            filename = rsp.get('FileName', None)
            if filename:
                url = '/download/' + filename
                savefile = os.path.join(directory, filename)
                fd = webclient.FileDownloader(self.wc, url, savefile)
                fd.start()
                while fd.isAlive():
                    fd.join(1)
                    self._refresh_token()
                yield savefile

    def apply_license(self, filename, progress=None, data=None):
        license_errors = {
            310: "License is for a different model of system",
            311: "License is for a different system serial number",
            312: "License is invalid",
            313: "License is expired",
            314: "License usage limit reached",
        }
        uploadthread = webclient.FileUploader(self.wc, '/upload', filename,
                                              data=data)
        uploadthread.start()
        uploadthread.join()
        rsp = json.loads(uploadthread.rsp)
        licpath = rsp.get('items', [{}])[0].get('path', None)
        if licpath:
            rsp = self.wc.grab_json_response(
                '/api/providers/imm_fod',
                {
                    'FOD_LicenseKeyInstall': licpath
                }
            )
            if rsp.get('return', 0) in license_errors:
                raise pygexc.InvalidParameterValue(
                    license_errors[rsp['return']])
        return self.get_licenses()

    def user_delete(self, uid):
        userinfo = self.wc.grab_json_response('/api/dataset/imm_users')
        uidtonamemap = {}
        for user in userinfo.get('items', [{'users': []}])[0].get('users', []):
            uidtonamemap[user['users_user_id']] = user['users_user_name']
        if uid in uidtonamemap:
            deltarget = '{0},{1}'.format(uid, uidtonamemap[uid])
            self.wc.grab_json_response('/api/function', {"USER_UserDelete": deltarget})
            return True
        return super(OEMHandler, self).user_delete(uid)

    def get_user_expiration(self, uid):
        userinfo = self.wc.grab_json_response('/api/dataset/imm_users')
        for user in userinfo['items'][0]['users']:
            if str(user['users_user_id']) == str(uid):
                days = user['users_pass_left_days']
                if days == 366:
                    return 0
                else:
                    return days

    def get_inventory_descriptions(self, withids=False):
        hwmap = self.hardware_inventory_map()
        yield "System"
        for key in natural_sort(hwmap):
            yield key

    def get_inventory_of_component(self, compname):
        if compname.lower() == 'system':
            sysinfo = {
                'UUID': self._varsysinfo.get('UUID', ''),
                'Serial Number': self._varsysinfo.get('SerialNumber', ''),
                'Manufacturer': self._varsysinfo.get('Manufacturer', ''),
                'Product Name': self._varsysinfo.get('Model', ''),
                'Model': self._varsysinfo.get(
                    'SKU', self._varsysinfo.get('PartNumber', '')),
            }
            return sysinfo
        hwmap = self.hardware_inventory_map()
        try:
            return hwmap[compname]
        except KeyError:

            return None

    def get_inventory(self, withids=False):
        sysinfo = {
            'UUID': self._varsysinfo.get('UUID', ''),
            'Serial Number': self._varsysinfo.get('SerialNumber', ''),
            'Manufacturer': self._varsysinfo.get('Manufacturer', ''),
            'Product Name': self._varsysinfo.get('Model', ''),
            'Model': self._varsysinfo.get(
                'SKU', self._varsysinfo.get('PartNumber', '')),
        }
        yield ('System', sysinfo)
        for cpuinv in self._get_cpu_inventory():
            yield cpuinv
        for meminv in self._get_mem_inventory():
            yield meminv
        hwmap = self.hardware_inventory_map()
        for key in natural_sort(hwmap):
            yield (key, hwmap[key])

    def hardware_inventory_map(self):
        hwmap = self.get_cached_data('lenovo_cached_hwmap')
        if hwmap:
            return hwmap
        hwmap = {}
        for disk in self.disk_inventory(mode=1):  # hardware mode
            hwmap[disk[0]] = disk[1]
        adapterdata = self.get_cached_data('lenovo_cached_adapters')
        if not adapterdata:
            if self.updating:
                raise pygexc.TemporaryError(
                    'Cannot read extended inventory during firmware update')
            if self.wc:
                adapterdata = self.wc.grab_json_response(self.ADP_URL)
                if adapterdata:
                    self.datacache['lenovo_cached_adapters'] = (
                        adapterdata, util._monotonic_time())
        if adapterdata and 'items' in adapterdata:
            anames = {}
            for adata in adapterdata['items']:
                skipadapter = False
                clabel = adata[self.ADP_LABEL]
                if clabel == 'Unknown':
                    continue
                if clabel != 'Onboard':
                    aslot = adata[self.ADP_SLOTNO]
                    if clabel == 'ML2':
                        clabel = 'ML2 (Slot {0})'.format(aslot)
                    else:
                        clabel = 'Slot {0}'.format(aslot)
                aname = adata[self.ADP_NAME]
                bdata = {'location': clabel, 'name': aname}
                if aname in anames:
                    anames[aname] += 1
                    aname = '{0} {1}'.format(aname, anames[aname])
                else:
                    anames[aname] = 1
                for fundata in adata[self.ADP_FUN]:
                    bdata['pcislot'] = '{0:02x}:{1:02x}'.format(
                        fundata[self.BUSNO], fundata[self.DEVNO])
                    serialdata = fundata.get(self.ADP_SERIALNO, None)
                    if (serialdata and serialdata != 'N/A'
                            and '---' not in serialdata):
                        bdata['serial'] = serialdata
                    partnum = fundata.get(self.ADP_PARTNUM, None)
                    if partnum and partnum != 'N/A':
                        bdata['Part Number'] = partnum
                    cardtype = funtypes.get(fundata.get('funType', None),
                                            None)
                    if cardtype is not None:
                        bdata['Type'] = cardtype
                    venid = fundata.get(self.ADP_VENID, None)
                    if venid is not None:
                        bdata['PCI Vendor ID'] = '{0:04x}'.format(venid)
                    devid = fundata.get(self.ADP_DEVID, None)
                    if devid is not None:
                        bdata['PCI Device ID'] = '{0:04x}'.format(devid)
                    venid = fundata.get(self.ADP_SUBVENID, None)
                    if venid is not None:
                        bdata['PCI Subsystem Vendor ID'] = '{0:04x}'.format(
                            venid)
                    devid = fundata.get(self.ADP_SUBDEVID, None)
                    if devid is not None:
                        bdata['PCI Subsystem Device ID'] = '{0:04x}'.format(
                            devid)
                    fruno = fundata.get(self.ADP_FRU, None)
                    if fruno is not None:
                        bdata['FRU Number'] = fruno
                    if self.PORTS in fundata:
                        for portinfo in fundata[self.PORTS]:
                            for lp in portinfo['logicalPorts']:
                                ma = lp['networkAddr']
                                ma = ':'.join(
                                    [ma[i:i + 2] for i in range(
                                        0, len(ma), 2)]).lower()
                                bdata['MAC Address {0}'.format(
                                    portinfo['portIndex'])] = ma
                    elif clabel == 'Onboard':  # skip the various non-nic
                        skipadapter = True
                if not skipadapter:
                    hwmap[aname] = bdata
            self.datacache['lenovo_cached_hwmap'] = (hwmap,
                                                     util._monotonic_time())
        # self.weblogout()
        return hwmap

    def disk_inventory(self, mode=0):
        # mode 0 is firmware, 1 is hardware
        storagedata = self.get_cached_data('lenovo_cached_storage')
        if not storagedata:
            if self.wc:
                storagedata = self.wc.grab_json_response(
                    '/api/function/raid_alldevices?params=storage_GetAllDisks')
                if storagedata:
                    self.datacache['lenovo_cached_storage'] = (
                        storagedata, util._monotonic_time())
        if storagedata and 'items' in storagedata:
            for adp in storagedata['items']:
                for diskent in adp.get('disks', ()):
                    if mode == 0:
                        yield self.get_disk_firmware(diskent)
                    elif mode == 1:
                        yield self.get_disk_hardware(diskent)
                for diskent in adp.get('aimDisks', ()):
                    if mode == 0:
                        yield self.get_disk_firmware(diskent)
                    elif mode == 1:
                        yield self.get_disk_hardware(diskent)
                if mode == 1:
                    bdata = {'Description': 'Unmanaged Disk'}
                    if adp.get('m2Type', -1) == 2:
                        yield 'M.2 Disk', bdata
                    for umd in adp.get('unmanagedDisks', []):
                        yield 'Disk {0}'.format(umd['slotNo']), bdata

    def _get_cpu_inventory(self):
        procdata = self.get_cached_data('lenovo_cached_proc')
        if not procdata:
            if self.wc:
                procdata = self.wc.grab_json_response(
                    '/api/dataset/imm_processors')
                if procdata:
                    self.datacache['lenovo_cached_proc'] = (
                        procdata, util._monotonic_time())
        if procdata:
            for proc in procdata.get('items', [{}])[0].get('processors', []):
                procinfo = {
                    'Model': proc['processors_cpu_model']
                }
                yield ('Processor {0}'.format(proc['processors_name']),
                       procinfo)

    def _get_mem_inventory(self):
        memdata = self.get_cached_data('lenovo_cached_memory')
        if not memdata:
            if self.wc:
                memdata = self.wc.grab_json_response(
                    '/api/dataset/imm_memory')
                if memdata:
                    self.datacache['lenovo_cached_memory'] = (
                        memdata, util._monotonic_time())
        if memdata:
            for dimm in memdata.get('items', [{}])[0].get('memory', []):
                memdata = {}
                memdata['speed'] = dimm['memory_mem_speed'] * 8 // 100 * 100
                memdata['module_type'] = 'RDIMM'
                memdata['capacity_mb'] = dimm['memory_capacity'] * 1024
                memdata['manufacturer'] = dimm['memory_manufacturer']
                memdata['memory_type'] = dimm['memory_type']
                memdata['model'] = dimm['memory_part_number'].rstrip()
                memdata['serial'] = dimm['memory_serial_number']
                yield (dimm['memory_name'], memdata)

    def get_disk_hardware(self, diskent, prefix=''):
        bdata = {}
        if not prefix and diskent.get('location', '').startswith('M.2'):
            prefix = 'M.2-'
        diskname = 'Disk {1}{0}'.format(diskent['slotNo'], prefix)
        bdata['Model'] = diskent['productName'].rstrip()
        bdata['Serial Number'] = diskent['serialNo'].rstrip()
        bdata['FRU Number'] = diskent['fruPartNo'].rstrip()
        bdata['Description'] = diskent['type'].rstrip()
        return (diskname, bdata)
