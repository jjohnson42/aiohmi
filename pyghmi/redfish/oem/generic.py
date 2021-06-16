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

import json
import os

import pyghmi.exceptions as exc
import pyghmi.media as media


class OEMHandler(object):
    hostnic = None

    def __init__(self, sysinfo, sysurl, webclient, cache, gpool=None):
        self._gpool = gpool
        self._varsysinfo = sysinfo
        self._varsysurl = sysurl
        self._urlcache = cache
        self.webclient = webclient

    def _get_cache(self, url):
        now = os.times()[4]
        cachent = self._urlcache.get(url, None)
        if cachent and cachent['vintage'] > now - 30:
            return cachent['contents']
        return None

    def get_bmc_configuration(self):
        return {}

    def set_bmc_configuration(self, changeset):
        raise exc.UnsupportedFunctionality(
            'Platform does not support setting bmc attributes')

    def attach_remote_media(self, url, username, password, vmurls):
        return None

    def detach_remote_media(self):
        return None

    def get_description(self):
        return {}

    def get_firmware_inventory(self, components):
        return []

    def set_credentials(self, username, password):
        try:
            self.username = username.decode('utf-8')
        except AttributeError:
            self.username = username
        try:
            self.password = password.decode('utf-8')
        except AttributeError:
            self.password = password

    def list_media(self, fishclient):
        bmcinfo = fishclient._do_web_request(fishclient._bmcurl)
        vmcoll = bmcinfo.get('VirtualMedia', {}).get('@odata.id', None)
        if vmcoll:
            vmlist = fishclient._do_web_request(vmcoll)
            vmurls = [x['@odata.id'] for x in vmlist.get('Members', [])]
            for vminfo in fishclient._do_bulk_requests(vmurls):
                vminfo = vminfo[0]
                if vminfo.get('Image', None):
                    imageurl = vminfo['Image'].replace(
                        '/' + vminfo['ImageName'], '')
                    yield media.Media(vminfo['ImageName'], imageurl)
                elif vminfo.get('Inserted', None) and vminfo.get(
                        'ImageName', None):
                    yield media.Media(vminfo['ImageName'])

    def get_inventory_descriptions(self, withids=False):
        yield "System"
        self._hwnamemap = {}
        for cpu in self._get_cpu_inventory(True, withids):
            yield cpu
        for mem in self._get_mem_inventory(True, withids):
            yield mem
        for adp in self._get_adp_inventory(True, withids):
            yield adp

    def get_inventory_of_component(self, component):
        if component.lower() == 'system':
            sysinfo = {
                'UUID': self._varsysinfo.get('UUID', ''),
                'Serial Number': self._varsysinfo.get('SerialNumber', ''),
                'Manufacturer': self._varsysinfo.get('Manufacturer', ''),
                'Product Name': self._varsysinfo.get('Model', ''),
                'Model': self._varsysinfo.get(
                    'SKU', self._varsysinfo.get('PartNumber', '')),
            }
            return sysinfo
        else:
            for invpair in self.get_inventory():
                if invpair[0].lower() == component.lower():
                    return invpair[1]

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
        self._hwnamemap = {}
        cpumemurls = []
        memurl = self._varsysinfo.get('Memory', {}).get('@odata.id', None)
        if memurl:
            cpumemurls.append(memurl)
        cpurl = self._varsysinfo.get('Processors', {}).get('@odata.id', None)
        if cpurl:
            cpumemurls.append(cpurl)
        list(self._do_bulk_requests(cpumemurls))
        adpurls = self._get_adp_urls()
        if cpurl:
            cpurls = self._get_cpu_urls()
        else:
            cpurls = []
        if memurl:
            memurls = self._get_mem_urls()
        else:
            memurls = []
        diskurls = self._get_disk_urls()
        allurls = adpurls + cpurls + memurls + diskurls
        list(self._do_bulk_requests(allurls))
        if cpurl:
            for cpu in self._get_cpu_inventory(withids=withids, urls=cpurls):
                yield cpu
        if memurl:
            for mem in self._get_mem_inventory(withids=withids, urls=memurls):
                yield mem
        for adp in self._get_adp_inventory(withids=withids, urls=adpurls):
            yield adp
        for disk in self._get_disk_inventory(withids=withids, urls=diskurls):
            yield disk

    def _get_disk_inventory(self, onlyname=False, withids=False, urls=None):
        if not urls:
            urls = self._get_disk_urls()
        for inf in self._do_bulk_requests(urls):
            inf, _ = inf
            ddata = {
                'Model': inf.get('Model', None),
                'Serial Number': inf.get('SerialNumber', None),
                'Description': inf.get('Name'),
            }
            loc = inf.get('PhysicalLocation', {}).get('Info', None)
            if loc:
                dname = 'Disk {0}'.format(loc)
            else:
                dname = inf.get('Id', 'Disk')
            yield (dname, ddata)

    def _get_adp_inventory(self, onlyname=False, withids=False, urls=None):
        if not urls:
            urls = self._get_adp_urls()
            if not urls:
                # No PCIe device inventory, but *maybe* ethernet inventory...
                aidx = 1
                for nicinfo in self._get_eth_urls():
                    nicinfo = self._do_web_request(nicinfo)
                    nicname = nicinfo.get('Name', None)
                    nicinfo = nicinfo.get('MACAddress', None)
                    if not nicname:
                        nicname = 'NIC'
                    if nicinfo:
                        yield (nicname,
                               {'MAC Address {0}'.format(aidx): nicinfo})
                        aidx += 1
                return
        for inf in self._do_bulk_requests(urls):
            adpinfo, url = inf
            aname = adpinfo.get('Name', 'Unknown')
            if aname in self._hwnamemap:
                aname = adpinfo.get('Id', aname)
            if aname in self._hwnamemap:
                self._hwnamemap[aname] = None
            else:
                self._hwnamemap[aname] = (url, self._get_adp_inventory)
            if onlyname:
                if withids:
                    yield aname, adpinfo.get('Id', aname)
                else:
                    yield aname
                continue
            functions = adpinfo.get('Links', {}).get('PCIeFunctions', [])
            nicidx = 1
            if withids:
                yieldinf = {'Id': adpinfo.get('Id', aname)}
            else:
                yieldinf = {}
            funurls = [x['@odata.id'] for x in functions]
            for fun in self._do_bulk_requests(funurls):
                funinfo, url = fun
                yieldinf['PCI Device ID'] = funinfo['DeviceId'].replace('0x',
                                                                        '')
                yieldinf['PCI Vendor ID'] = funinfo['VendorId'].replace('0x',
                                                                        '')
                yieldinf['PCI Subsystem Device ID'] = funinfo[
                    'SubsystemId'].replace('0x', '')
                yieldinf['PCI Subsystem Vendor ID'] = funinfo[
                    'SubsystemVendorId'].replace('0x', '')
                yieldinf['Type'] = funinfo['DeviceClass']
                for nicinfo in funinfo.get('Links', {}).get(
                        'EthernetInterfaces', []):
                    nicinfo = self._do_web_request(nicinfo['@odata.id'])
                    macaddr = nicinfo.get('MACAddress', None)
                    if macaddr:
                        yieldinf['MAC Address {0}'.format(nicidx)] = macaddr
                        nicidx += 1
            yield aname, yieldinf

    def _get_eth_urls(self):
        ethurls = self._varsysinfo.get('EthernetInterfaces', {})
        ethurls = ethurls.get('@odata.id', None)
        if ethurls:
            ethurls = self._do_web_request(ethurls)
            ethurls = ethurls.get('Members', [])
            urls = [x['@odata.id'] for x in ethurls]
        else:
            urls = []
        return urls

    def _get_adp_urls(self):
        adpurls = self._varsysinfo.get('PCIeDevices', [])
        if adpurls:
            urls = [x['@odata.id'] for x in adpurls]
        else:
            urls = []
        return urls

    def _get_cpu_inventory(self, onlynames=False, withids=False, urls=None):
        if not urls:
            urls = self._get_cpu_urls()
        if not urls:
            return
        for res in self._do_bulk_requests(urls):
            currcpuinfo, url = res
            name = currcpuinfo.get('Name', 'CPU')
            if name in self._hwnamemap:
                self._hwnamemap[name] = None
            else:
                self._hwnamemap[name] = (url, self._get_cpu_inventory)
            if onlynames:
                yield name
                continue
            cpuinfo = {'Model': currcpuinfo.get('Model', None)}
            yield name, cpuinfo

    def _get_disk_urls(self):
        storurl = self._varsysinfo.get('Storage', {}).get('@odata.id', None)
        urls = []
        if storurl:
            storurl = self._do_web_request(storurl)
            for url in storurl.get('Members', []):
                url = url['@odata.id']
                ctldata = self._do_web_request(url)
                for durl in ctldata.get('Drives', []):
                    urls.append(durl['@odata.id'])
        return urls

    def _get_cpu_urls(self):
        cpurl = self._varsysinfo.get('Processors', {}).get('@odata.id', None)
        if cpurl is None:
            urls = []
        else:
            cpurl = self._do_web_request(cpurl)
            urls = [x['@odata.id'] for x in cpurl.get('Members', [])]
        return urls

    def _get_mem_inventory(self, onlyname=False, withids=False, urls=None):
        if not urls:
            urls = self._get_mem_urls()
        if not urls:
            return
        for mem in self._do_bulk_requests(urls):
            currmeminfo, url = mem
            name = currmeminfo.get('Name', 'Memory')
            if name in self._hwnamemap:
                self._hwnamemap[name] = None
            else:
                self._hwnamemap[name] = (url, self._get_mem_inventory)
            if onlyname:
                yield name
                continue
            if currmeminfo.get(
                    'Status', {}).get('State', 'Absent') == 'Absent':
                yield (name, None)
                continue
            currspeed = currmeminfo.get('OperatingSpeedMhz', None)
            if currspeed:
                currspeed = int(currspeed)
                currspeed = currspeed * 8 - (currspeed * 8 % 100)
            meminfo = {
                'capacity_mb': currmeminfo.get('CapacityMiB', None),
                'manufacturer': currmeminfo.get('Manufacturer', None),
                'memory_type': currmeminfo.get('MemoryDeviceType', None),
                'model': currmeminfo.get('PartNumber', None),
                'module_type': currmeminfo.get('BaseModuleType', None),
                'serial': currmeminfo.get('SerialNumber', None),
                'speed': currspeed,
            }
            yield (name, meminfo)

    def _get_mem_urls(self):
        memurl = self._varsysinfo.get('Memory', {}).get('@odata.id', None)
        if not memurl:
            urls = []
        else:
            memurl = self._do_web_request(memurl)
            urls = [x['@odata.id'] for x in memurl.get('Members', [])]
        return urls

    def get_storage_configuration(self):
        raise exc.UnsupportedFunctionality(
            'Remote storage configuration not supported on this platform')

    def remove_storage_configuration(self, cfgspec):
        raise exc.UnsupportedFunctionality(
            'Remote storage configuration not supported on this platform')

    def apply_storage_configuration(self, cfgspec):
        raise exc.UnsupportedFunctionality(
            'Remote storage configuration not supported on this platform')

    def upload_media(self, filename, progress=None, data=None):
        raise exc.UnsupportedFunctionality(
            'Remote media upload not supported on this platform')

    def update_firmware(self, filename, data=None, progress=None, bank=None):
        raise exc.UnsupportedFunctionality(
            'Firmware update not supported on this platform')

    def _do_bulk_requests(self, urls, cache=True):
        if self._gpool:
            urls = [(x, None, None, cache) for x in urls]
            for res in self._gpool.starmap(self._do_web_request_withurl, urls):
                yield res
        else:
            for url in urls:
                yield self._do_web_request_withurl(url, cache=cache)

    def _do_web_request_withurl(self, url, payload=None, method=None,
                                cache=True):
        return self._do_web_request(url, payload, method, cache), url

    def _do_web_request(self, url, payload=None, method=None, cache=True):
        res = None
        if cache and payload is None and method is None:
            res = self._get_cache(url)
        if res:
            return res
        wc = self.webclient.dupe()
        res = wc.grab_json_response_with_status(url, payload, method=method)
        if res[1] < 200 or res[1] >= 300:
            try:
                info = json.loads(res[0])
                errmsg = [
                    x.get('Message', x['MessageId']) for x in info.get(
                        'error', {}).get('@Message.ExtendedInfo', {})]
                errmsg = ','.join(errmsg)
                raise exc.RedfishError(errmsg)
            except (ValueError, KeyError):
                raise exc.PyghmiException(str(url) + ":" + res[0])
        if payload is None and method is None:
            self._urlcache[url] = {
                'contents': res[0],
                'vintage': os.times()[4]
            }
        return res[0]

    def get_diagnostic_data(self, savefile, progress=None, autosuffix=None):
        """Download diagnostic data about target to a file

        This should be a payload that the vendor's support team can use
        to do diagnostics.
        :param savefile: File object or filename to save to
        :param progress: Callback to be informed about progress
        :param autosuffix: Have the library automatically amend filename per
                           vendor support requirements.
        :return:
        """
        raise exc.UnsupportedFunctionality(
            'Retrieving diagnostic data is not implemented for this platform')

    def get_licenses(self):
        raise exc.UnsupportedFunctionality()

    def delete_license(self, name):
        raise exc.UnsupportedFunctionality()

    def save_licenses(self, directory):
        raise exc.UnsupportedFunctionality()

    def apply_license(self, filename, progress=None, data=None):
        raise exc.UnsupportedFunctionality()

    def get_user_expiration(self, uid):
        return None

    def reseat_bay(self, bay):
        raise exc.UnsupportedFunctionality(
            'Bay reseat not supported on this platform')
