# Copyright 2025 Lenovo Corporation
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
import copy
import json
import aiohmi.constants as pygconst
import aiohmi.redfish.oem.generic as generic
import aiohmi.exceptions as pygexc
import aiohmi.util.webclient as webclient
import os.path
import zipfile


class SensorReading(object):
    def __init__(self, healthinfo, sensor=None, value=None, units=None,
                 unavailable=False):
        if sensor:
            self.name = sensor['name']
        else:
            self.name = healthinfo['name']
            self.health = healthinfo['health']
            self.states = healthinfo['states']
            self.state_ids = healthinfo.get('state_ids', None)
        self.value = value
        self.imprecision = None
        self.units = units
        self.unavailable = unavailable

class OEMHandler(generic.OEMHandler):

    async def supports_expand(self, url):
        return True

    async def get_screenshot(self, outfile):
        wc = self.webclient.dupe()
        self._get_session_token(wc)
        url = '/web_download/Mini_ScreenShot.jpg'
        fd = webclient.FileDownloader(wc, url, outfile)
        fd.start()
        fd.join()

    def get_diagnostic_data(self, savefile, progress=None, autosuffix=False):
        tsk = self._do_web_request(
            '/redfish/v1/Systems/1/LogServices/DiagnosticLog/Actions/LogService.CollectDiagnosticData',
            {"DiagnosticDataType": "Manager", "SelectDataTypes": []})
        taskrunning = True
        taskurl = tsk.get('TaskMonitor', None)
        pct = 0 if taskurl else 100
        durl = None
        while pct < 100 and taskrunning:
            status = self._do_web_request(taskurl)
            durl = status.get('AdditionalDataURI', '')
            pct = status.get('PercentComplete', 0)
            taskrunning = status.get('TaskState', 'Complete') == 'Running'
            if progress:
                progress({'phase': 'initializing', 'progress': float(pct)})
            if taskrunning:
                await asyncio.sleep(3)
        if not durl:
            raise Exception("Failed getting service data url")
        fname = os.path.basename(durl)
        if autosuffix and not savefile.endswith('.tar.zst'):
            savefile += '-{0}'.format(fname)
        fd = webclient.FileDownloader(self.webclient, durl, savefile)
        fd.start()
        while fd.isAlive():
            fd.join(1)
            if progress and self.webclient.get_download_progress():
                progress({'phase': 'download',
                          'progress': 100 * self.webclient.get_download_progress()})
        if fd.exc:
            raise fd.exc
        if progress:
            progress({'phase': 'complete'})
        return savefile

    async def get_ikvm_methods(self):
        return ['openbmc', 'url']

    async def get_ikvm_launchdata(self):
        access = await self._do_web_request('/redfish/v1/Managers/1/Oem/Lenovo/RemoteControl/Actions/LenovoRemoteControlService.GetRemoteConsoleToken', {})
        if access.get('Token', None):
            accessinfo = {
                'url': '/#/login?{}&context=remote&mode=multi'.format(access['Token'])
                }
            return accessinfo

    def get_system_power_watts(self, fishclient):
        powerinfo = fishclient._do_web_request('/redfish/v1/Chassis/1/Sensors/power_Sys_Power')
        return powerinfo['Reading']
    
    async def get_health(self, fishclient, verbose=True):
        rsp = await self._do_web_request('/api/providers/imm_active_events')
        summary = {'badreadings': [], 'health': pygconst.Health.Ok}
        fallbackdata = []
        hmap = {
            0 : pygconst.Health.Ok,
            3: pygconst.Health.Critical,
            2: pygconst.Health.Warning,
        }
        infoevents = False
        existingevts = set([])
        for item in rsp.get('items', ()):
            # while usually the ipmi interrogation shall explain things,
            # just in case there is a gap, make sure at least the
            # health field is accurately updated
            itemseverity = hmap.get(item.get('Severity', 2),
                                    pygconst.Health.Critical)
            if itemseverity == pygconst.Health.Ok:
                infoevents = True
                continue
            if (summary['health'] < itemseverity):
                summary['health'] = itemseverity
            evtsrc = item.get('Oem', {}).get('Lenovo', {}).get('Source', '')
            currevt = '{}:{}'.format(evtsrc, item['Message'])
            if currevt in existingevts:
                continue
            existingevts.add(currevt)
            fallbackdata.append(SensorReading({
                'name': evtsrc,
                'states': [item['Message']],
                'health': itemseverity,
                'type': evtsrc,
            }, ''))
        summary['badreadings'] = fallbackdata
        return summary   

    def _get_cpu_temps(self, fishclient):
        cputemps = []
        for reading in super()._get_cpu_temps(fishclient):
            if 'Margin' in reading['Name']:
                continue
            cputemps.append(reading)
        return cputemps

    def get_system_configuration(self, hideadvanced=True, fishclient=None):
        stgs = self._getsyscfg(fishclient)[0]
        outstgs = {}
        for stg in stgs:
            outstgs[f'UEFI.{stg}'] = stgs[stg]
        return outstgs

    def set_system_configuration(self, changeset, fishclient):
        bmchangeset = {}
        vpdchangeset = {}
        for stg in list(changeset):
            if stg.startswith('BMC.'):
                bmchangeset[stg.replace('BMC.', '')] = changeset[stg]
                del changeset[stg]
            if stg.startswith('UEFI.'):
                changeset[stg.replace('UEFI.', '')] = changeset[stg]
                del changeset[stg]
            if stg.startswith('VPD.'):
                vpdchangeset[stg.replace('VPD.', '')] = changeset[stg]
                del changeset[stg]
        if changeset:
            super().set_system_configuration(changeset, fishclient)
        if bmchangeset:
            self._set_xcc3_settings(bmchangeset, fishclient)
        if vpdchangeset:
            self._set_xcc3_vpd(vpdchangeset, fishclient)

    def _set_xcc3_vpd(self, changeset, fishclient):
        newvpd = {'Attributes': changeset}
        fishclient._do_web_request(
            '/redfish/v1/Chassis/1/Oem/Lenovo/SysvpdSettings/Actions/LenovoSysVpdSettings.SetVpdSettings',
            newvpd)


    def _set_xcc3_settings(self, changeset, fishclient):
        currsettings, reginfo = self._get_lnv_bmcstgs(fishclient)
        rawsettings = fishclient._do_web_request('/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings',
                                                 cache=False)
        rawsettings = rawsettings.get('Attributes', {})
        pendingsettings = {}
        ret = self._set_redfish_settings(
            changeset, fishclient, currsettings, rawsettings,
            pendingsettings, self.lenovobmcattrdeps, reginfo,
            '/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings')
        fishclient._do_web_request('/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings', cache=False)
        return ret

    oemacctmap = {
        'password_reuse_count': 'MinimumPasswordReuseCycle',
        'password_change_interval':  'MinimumPasswordChangeIntervalHours',
        'password_expiration': 'PasswordExpirationPeriodDays',
        'password_complexity': 'ComplexPassword',
        }

    acctmap = {
        'password_login_failures': 'AccountLockoutThreshold',
        'password_min_length': 'MinPasswordLength',
        'password_lockout_period': 'AccountLockoutDuration',
        }

    def update_firmware(self, filename, data=None, progress=None, bank=None, otherfields=()):
        if not otherfields and bank == 'backup':
            uxzcount = 0
            otherfields = {'UpdateParameters': {"Targets": ["/redfish/v1/UpdateService/FirmwareInventory/BMC-Backup"]}}
            needseek = False
            if data and hasattr(data, 'read'):
                if zipfile.is_zipfile(data):
                    needseek = True
                    z = zipfile.ZipFile(data)
                else:
                    data.seek(0)
            elif data is None and zipfile.is_zipfile(filename):
                z = zipfile.ZipFile(filename)
            if z:
                for tmpname in z.namelist():
                    if tmpname.startswith('payloads/'):
                        uxzcount += 1
                        if tmpname.endswith('.uxz'):
                            wrappedfilename = tmpname
            if uxzcount == 1 and wrappedfilename:
                filename = os.path.basename(wrappedfilename)
                data = z.open(wrappedfilename)
            elif needseek:
                data.seek(0)
        super().update_firmware(filename, data=data, progress=progress, bank=bank, otherfields=otherfields)


    def get_bmc_configuration(self):
        settings = {}
        acctsrv = self._do_web_request('/redfish/v1/AccountService')
        for oemstg in self.oemacctmap:
            settings[oemstg] = {
                'value': acctsrv['Oem']['Lenovo'][self.oemacctmap[oemstg]]}
        for stg in self.acctmap:
            settings[stg] = {
                'value': acctsrv[self.acctmap[stg]]}
        bmcstgs = self._do_web_request('/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings')
        bmcattrs = bmcstgs['Attributes']
        self.ethoverusb = True if 'EthOverUSBEnabled' in bmcattrs else False
        usbcfg = bmcattrs.get('NetMgrUsb0Enabled', bmcattrs.get('EthOverUSBEnabled', 'False'))
        usbeth = 'Enable' if usbcfg == 'True' else 'Disable'
        settings['usb_ethernet'] = {
            'value': usbeth
        }
        usbcfg = bmcattrs.get('NetMgrUsb0PortForwardingEnabled', bmcattrs.get('EthOverUSBPortForwardingEnabled', 'False'))
        fwd = 'Enable' if usbcfg == 'True' else 'Disable'
        settings['usb_ethernet_port_forwarding'] = fwd
        mappings = []
        for idx in range(1, 11):
            keyname = 'NetMgrUsb0PortForwardingPortMapping.{}'.format(idx)
            keyaltname = 'EthOverUSBPortForwardingPortMapping_{}'.format(idx)
            currval = bmcattrs.get(keyname, bmcattrs.get(keyaltname, '0,0'))
            if currval == '0,0':
                continue
            src, dst = currval.split(',')
            mappings.append('{}:{}'.format(src,dst))
        settings['usb_forwarded_ports'] = {'value': ','.join(mappings)}
        return settings

    def set_bmc_configuration(self, changeset):
        acctattribs = {}
        usbsettings = {}
        for key in changeset:
            if isinstance(changeset[key], str):
                changeset[key] = {'value': changeset[key]}
            currval = changeset[key].get('value', None)
            if key == 'password_complexity':
                if currval.lower() in ("false", 0):
                    currval = False
                elif currval.lower() in ('true', 1):
                    currval = True
            elif key.lower().startswith('usb_'):
                if 'forwarded_ports' not in key.lower():
                    currval = currval.lower()
                    if currval and 'disabled'.startswith(currval):
                        currval = 'False'
                    elif currval and 'enabled'.startswith(currval):
                        currval = 'True'
            else:
                currval = int(currval)
            if key.lower() in self.oemacctmap:
                if 'Oem' not in acctattribs:
                    acctattribs['Oem'] = {'Lenovo': {}}
                acctattribs['Oem']['Lenovo'][
                    self.oemacctmap[key.lower()]] = currval
                if key.lower() == 'password_expiration':
                    warntime = int(int(currval) * 0.08)
                    acctattribs['Oem']['Lenovo'][
                        'PasswordExpirationWarningPeriod'] = warntime
            elif key.lower() in self.acctmap:
                acctattribs[self.acctmap[key.lower()]] = currval
            elif key.lower() in (
                    'usb_ethernet', 'usb_ethernet_port_forwarding',
                    'usb_forwarded_ports'):
                usbsettings[key] = currval
            else:
                raise pygexc.InvalidParameterValue(
                    '{0} not a known setting'.format(key))
        if acctattribs:
            self._do_web_request(
                '/redfish/v1/AccountService', acctattribs, method='PATCH')
            self._do_web_request('/redfish/v1/AccountService', cache=False)
        if usbsettings:
            self.apply_usb_configuration(usbsettings)

    def apply_usb_configuration(self, usbsettings):
        bmcattribs = {}
        if not hasattr(self, 'ethoverusb'):
            self.get_bmc_configuration()
        if 'usb_forwarded_ports' in usbsettings:
            pairs = usbsettings['usb_forwarded_ports'].split(',')
            idx = 1
            for pair in pairs:
                if self.ethoverusb:
                    keyname = 'EthOverUSBPortForwardingPortMapping_{}'.format(idx)
                else:
                    keyname = 'NetMgrUsb0PortForwardingPortMapping.{}'.format(idx)
                pair = pair.replace(':', ',')
                if self.ethoverusb:
                    keyname = 'EthOverUSBPortForwardingPortMapping_{}'.format(idx)
                else:
                    keyname = 'NetMgrUsb0PortForwardingPortMapping.{}'.format(idx)
                bmcattribs[keyname] = '0,0'
                idx += 1
            while idx < 11:
                bmcattribs[
                    'NetMgrUsb0PortForwardingPortMapping.{}'.format(
                        idx)] = '0,0'
                idx += 1
        if 'usb_ethernet' in usbsettings:
            keyname = 'EthOverUSBEnabled' if self.ethoverusb else 'NetMgrUsb0Enabled'
            bmcattribs[keyname] = usbsettings['usb_ethernet']
        if 'usb_ethernet_port_forwarding' in usbsettings:
            keyname = 'EthOverUSBPortForwardingEnabled' if self.ethoverusb else 'NetMgrUsb0PortForwardingEnabled'
            bmcattribs[keyname] = usbsettings[
                    'usb_ethernet_port_forwarding']
        self._do_web_request(
            '/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings',
            {'Attributes': bmcattribs}, method='PATCH')
        self._do_web_request(
            '/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings', cache=False)

    def get_extended_bmc_configuration(self, fishclient, hideadvanced=True):
        cfgin = self._get_lnv_bmcstgs(fishclient)[0]
        cfgout = {}
        for stgname in cfgin:
            cfgout[f'BMC.{stgname}'] = cfgin[stgname]
        vpdin = self._get_lnv_vpd(fishclient)[0]
        for stgname in vpdin:
            cfgout[f'VPD.{stgname}'] = vpdin[stgname]
        return cfgout

    def _get_lnv_vpd(self, fishclient):
        currsettings, reginfo = self._get_lnv_stgs(
            fishclient, '/redfish/v1/Chassis/1/Oem/Lenovo/SysvpdSettings')
        self.lenovobmcattrdeps = reginfo[3]
        return currsettings, reginfo

    def _get_lnv_bmcstgs(self, fishclient):
        currsettings, reginfo = self._get_lnv_stgs(
            fishclient, '/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings')
        self.lenovobmcattrdeps = reginfo[3]
        return currsettings, reginfo

    def _get_lnv_stgs(self, fishclient, url):
        bmcstgs = fishclient._do_web_request(url)
        bmcreg = bmcstgs.get('AttributeRegistry', None)
        extrainfo = {}
        valtodisplay = {}
        currsettings = {}
        reginfo = {}, {}, {}, {}
        if bmcreg:
            reginfo = self._get_attrib_registry(fishclient, bmcreg)
            if reginfo:
                extrainfo, valtodisplay, _, _ = reginfo
        for setting in bmcstgs.get('Attributes', {}):
            val = bmcstgs['Attributes'][setting]
            currval = val
            val = valtodisplay.get(setting, {}).get(val, val)
            val = {'value': val}
            val.update(**extrainfo.get(setting, {}))
            currsettings[setting] = val
        return currsettings, reginfo

    async def get_description(self, fishclient):
        rsp = await self._get_expanded_data('/redfish/v1/Chassis')
        for chassis in rsp['Members']:
            if (chassis['@odata.id'] == '/redfish/v1/Chassis/1'
                    and chassis['ChassisType'] != 'Blade'):
                hmm = chassis.get('HeightMm', None)
                if hmm:
                    return {'height': hmm/44.45}
            if (chassis['@odata.id'] == '/redfish/v1/Chassis/Enclosure'
                    and chassis.get('ChassisType', None) == 'Enclosure'):
                try:
                    slot = chassis['Location']['PartLocation']['LocationOrdinalValue']
                    slotnum = (2 * (slot >> 4) - 1) + ((slot & 15) % 10)
                    slotcoord = [slot >> 4, (slot & 15) - 9]
                    return {'slot': slotnum, 'slotlabel': '{:02x}'.format(slot), 'slotcoord': slotcoord}
                except KeyError:
                    continue
        return {}

    def upload_media(self, filename, progress=None, data=None):
        wc = self.webclient
        uploadthread = webclient.FileUploader(
            wc, '/rdoc_upload', filename, data,
            formname='file',
            formwrap=True)
        uploadthread.start()
        while uploadthread.isAlive():
            uploadthread.join(3)
            if progress:
                progress({'phase': 'upload',
                          'progress': 100 * wc.get_upload_progress()})
        rsp = json.loads(uploadthread.rsp)
        if rsp['return'] != 0:
            raise Exception('Issue uploading file')
        remfilename = rsp['upload_filename']
        if progress:
            progress({'phase': 'upload',
                      'progress': 100.0})
        self._do_web_request(
            '/redfish/v1/Systems/1/VirtualMedia/RDOC1',
            {'Image':'file:///gpx/rdocupload/' + remfilename,
             'WriteProtected': False}, method='PATCH')
        if progress:
            progress({'phase': 'complete'})

    async def get_firmware_inventory(self, components, fishclient):
        sfs = await fishclient._do_web_request('/api/providers/system_firmware_status')
        pendingscm = sfs.get('fpga_scm_pending_build', None)
        pendinghpm = sfs.get('fpga_hpm_pending_build', None)
        if pendingscm == '*':
            pendingscm = None
        if pendinghpm == '*':
            pendinghpm = None    
        fwlist = await fishclient._do_web_request(fishclient._fwinventory + '?$expand=.')
        fwlist = copy.deepcopy(fwlist.get('Members', []))
        self._fwnamemap = {}
        for redres in fwlist:
            fwurl = redres['@odata.id']
            res = (redres, fwurl)
            if fwurl.startswith('/redfish/v1/UpdateService/FirmwareInventory/Bundle.'):
                continue  # skip Bundle information for now
            if redres.get('Name', '').startswith('Firmware:'):
                redres['Name'] = redres['Name'].replace('Firmware:', '')
            if redres['Name'].startswith('Firmware-PSoC') and 'Drive_Backplane' in redres["@odata.id"]:
                redres['Name'] = 'Drive Backplane'
            if redres['Name'].startswith('DEVICE-'):
                redres['Name'] = redres['Name'].replace('DEVICE-', '')
            if redres['Name'].startswith('POWER-PSU'):
                redres['Name'] = redres['Name'].replace('POWER-', '')
            swid = redres.get('SoftwareId', '')
            buildid = ''
            version = redres.get('Version', None)
            for prefix in ['FPGA-', 'UEFI-', 'BMC-', 'LXPM-', 'DRVWN-', 'DRVLN-', 'LXUM']:
                if swid.startswith(prefix):
                    buildid = swid.split('-')[1] + version.split('-')[0]
                    version = '-'.join(version.split('-')[1:])
                    break
            if version:
                redres['Version'] = version
            cres = fishclient._extract_fwinfo(res)
            if cres[0] is None:
                continue
            if buildid:
                cres[1]['build'] = buildid
            yield cres
            if cres[0] == 'SCM-FPGA' and pendingscm:
                yield 'SCM-FPGA Pending', {
                    'Name': 'SCM-FPGA Pending',
                    'build': pendingscm}
            elif cres[0] == 'HPM-FPGA' and pendinghpm:
                yield 'HPM-FPGA Pending', {
                    'Name': 'HPM-FPGA Pending',
                    'build': pendinghpm}
        raise pygexc.BypassGenericBehavior()


