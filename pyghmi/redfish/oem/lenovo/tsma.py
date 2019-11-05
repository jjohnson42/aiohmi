# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2015-2017 Lenovo
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
import pyghmi.exceptions as exc
import pyghmi.util.webclient as webclient
import struct
import time
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode
import weakref

hpm_by_filename = {}

class HpmSection(object):
    __slots__ = ['comp_id', 'comp_ver', 'comp_name', 'section_flash', 'data', 'hash_size', 'combo_image']

def read_hpm(filename):
    hpminfo = []
    with open(filename, 'rb') as hpmfile:
        hpmfile.seek(0x20)
        skip = struct.unpack('>H', hpmfile.read(2))[0]
        hpmfile.seek(skip + 1, 1) 
        sectype, compid = struct.unpack('BB', hpmfile.read(2))
        while sectype == 2:
            currsec = HpmSection()
            currsec.comp_id = compid
            hpmfile.seek(1, 1)
            major, minor, pat = struct.unpack('<BBI', hpmfile.read(6))
            currsec.comp_ver = '{0}.{1}.{2}'.format(major, minor, pat)
            currsec.comp_name = hpmfile.read(21).rstrip(b'\x00')
            currlen = struct.unpack('<I', hpmfile.read(4))[0] - 16
            oemstr = hpmfile.read(4)
            if oemstr != b'OEM\x00':
                raise Exception('Unrecognized HPM field near {0}'.format(hpmfile.tell()))
            currsec.section_flash = struct.unpack('<I', hpmfile.read(4))[0]
            hashpresent, hdrsize, blocks = struct.unpack('BBB', hpmfile.read(3))
            if hashpresent != 1:
                hashpresent = 0
            currsec.hash_size = hashpresent * (256 * blocks + hdrsize)
            hpmfile.seek(5, 1) 
            currsec.data = hpmfile.read(currlen)
            hpminfo.append(currsec)
            sectype, compid = struct.unpack('BB', hpmfile.read(2))
        upimg = hpminfo[1].data[:-hpminfo[1].hash_size] + hpminfo[2].data[:-hpminfo[2].hash_size]
        hpminfo[2].combo_image = upimg
        hpminfo[1].combo_image = upimg
        currpos = hpmfile.tell()
        hpmfile.seek(0, 2)
        endpos = hpmfile.tell()
        if currpos < (endpos - 512):
            raise Exception("Unexpected end of HPM file")
    return hpminfo



class TsmHandler(generic.OEMHandler):
    hostnic = 'usb0'
    def __init__(self, sysinfo, sysurl, webclient, cache=None, fish=None):
        if cache is None:
            cache = {}
        self._wc = None
        self.username = None
        self.password = None
        self._wc = None
        self.csrftok = None
        self.fish = fish
        super(TsmHandler, self).__init__(sysinfo, sysurl, webclient, cache)
        self.tsm = webclient.thehost
        self._certverify = webclient._certverify

    def get_uefi_configuration(self, hideadvanced=True):
        return self.fishclient.get_system_configuration(hideadvanced)

    def init_redfish(self):
        self.fishclient = self.fish.Command(self.tsm, self.username, self.password,
            verifycallback=self._certverify)

    def get_firmware_inventory(self, components, raisebypass=True):
        wc = self.wc
        fwinf, status = wc.grab_json_response_with_status(
            '/api/DeviceVersion')
        gotinfo = False
        if status < 200 or status >= 300:
            raise Exception('Error connecting to HTTP API')
        for biosinf in fwinf:
            if biosinf.get('device', None) != 1:
                continue
            if not biosinf.get('buildname', False):
                break
            biosres = {
                'build': biosinf['buildname']
            }
            if biosinf.get('main', False):
                biosres['version'] = '{0}.{1}'.format(
                    biosinf['main'][0], biosinf['main'][1:]),
            yield ('UEFI', biosres)
            gotinfo = True
            break
        name = 'TSM'
        fwinf = wc.grab_json_response('/api/get-sysfwinfo')
        for cinf in fwinf:
            bmcinf = {
                'version': cinf['fw_ver'],
                'build': cinf['buildname'],
                'date': cinf['builddate'],
            }
            yield (name, bmcinf)
            gotinfo = True
            name += ' Backup'
        if not gotinfo:
            raise Exception("Unable to retrieve firmware information")
        if raisebypass:
            raise exc.BypassGenericBehavior()

    @property
    def wc(self):
        self.fwid = None
        if self._wc:
            return self._wc
        authdata = {
            'username': self.username,
            'password': self.password,
        }
        wc = webclient.SecureHTTPConnection(self.tsm, 443, verifycallback=self._certverify, timeout=180)
        wc.set_header('Content-Type', 'application/json')
        rsp, status = wc.grab_json_response_with_status('/api/session', authdata)
        if status == 403:
            wc.set_header('Content-Type', 'application/x-www-form-urlencoded')
            rsp, status = wc.grab_json_response_with_status('/api/session', urlencode(authdata))

        if status < 200 or status >= 300:
            raise Exception('Error establishing web session')
        self.csrftok = rsp['CSRFToken']
        wc.set_header('X-CSRFTOKEN', self.csrftok)
        self._wc = wc
        return wc
    
    def update_firmware(self, filename, data=None, progress=None, bank=None):
        wc = self.wc
        wc.set_header('Content-Type', 'application/json')
        if filename.endswith('.hpm'):
            self.update_hpm_firmware(filename, progress, wc)
        elif 'uefi' in filename and filename.endswith('.rom'):
            self.update_uefi_firmware(filename, progress, wc)
        else:
            raise Exception('Unsupported filename {0}'.format(filename))

    def update_uefi_firmware(self, filename, progress, wc):
        rsp = wc.grab_json_response_with_status(
            '/api/maintenance/BIOSremoteSave', {"tftpip":"","tftpfile":""})
        hdrs = wc.stdheaders.copy()
        hdrs['Content-Length'] = 0
        rsp = wc.grab_json_response_with_status(
            '/api/maintenance/flash', method='PUT', headers=hdrs)
        fu = webclient.FileUploader(
            wc, '/api/maintenance/firmware/BIOS', filename, formname='fwimage')
        fu.start()
        while fu.isAlive():
            fu.join(3)
            if progress:
                progress({
                    'phase': 'upload',
                    'progress': 100 * wc.get_upload_progress()})
        if progress:
            progress({
                        'phase': 'apply',
                        'progress': 0.0})
        rsp = wc.grab_json_response_with_status('/api/maintenance/BIOSstart')
        applypct = 0.0
        if rsp[1] >= 200 and rsp[1] < 300 and rsp[0]['wRet'] == 0:
            updone = False
            while not updone:
                rsp = wc.grab_json_response('/api/maintenance/BIOSstatus')
                if rsp.get('state', 0) == 9:
                    break
                if rsp.get('state', 0) in (6, 10):
                    raise Exception('Update Failure')
                if (rsp.get('state', 0) == 8 and rsp.get('progress', 0) > 0
                        and progress):
                    progress({
                        'phase': 'apply',
                        'progress': 70 + float(rsp.get('progress', 0))/100*30})
                elif progress and applypct < 70:
                    applypct += 1.4
                    progress({'phase': 'apply', 'progress': applypct})
            return 'pending'
        raise Exception('Update Failure')

    def update_hpm_firmware(self, filename, progress, wc):
        rsp = wc.grab_json_response('/api/maintenance/hpm/freemem')
        if 'MemFree' not in rsp:
            raise Exception('System Not Ready for update')
        if filename not in hpm_by_filename:
            hpminfo = read_hpm(filename)
            if len(hpminfo) != 3:
                raise Exception(
                    'This HPM update is currently not supported')
            hpm_by_filename[filename] = read_hpm(filename)
        else:
            hpminfo = hpm_by_filename[filename]
        rsp, status = wc.grab_json_response_with_status(
            '/api/maintenance/hpm/updatemode', method='PUT')
        # first segment, make sure it is mmc,
        # then do the preparecomponents with the following payload
        if status != 200:
            raise Exception(rsp)
        uid = rsp['unique_id']
        self.fwid = uid
        payload = {
            'FWUPDATEID': uid,
            'COMPONENT_ID': 1,
            'COMPONENT_DATA_LEN': len(hpminfo[0].data),
            'IS_MMC': 1,
        }
        rsp, status = wc.grab_json_response_with_status(
            '/api/maintenance/hpm/preparecomponents', payload, method='PUT')
        if status < 200 or status >= 300:
            err = wc.grab_json_response_with_status(
                '/api/maintenance/hpm/exitupdatemode', {'FWUPDATEID': uid},
                method='PUT')
            raise Exception(rsp)
        fu = webclient.FileUploader(
            wc, '/api/maintenance/hpm/mmcfw', 'blob', hpminfo[0].data, 'mmc')
        if progress:
            progress({'phase': 'upload', 'progress': 0.0})
        fu.start()
        while fu.isAlive():
            fu.join(3)
            if progress:
                progress({
                    'phase': 'upload',
                    'progress': 50 * wc.get_upload_progress()})
        del payload['IS_MMC']
        payload['SECTION_FLASH'] = hpminfo[0].section_flash
        rsp, status = wc.grab_json_response_with_status(
            '/api/maintenance/hpm/flash', payload, method='PUT')
        percent = 0
        while percent < 100:
            rsp, status = wc.grab_json_response_with_status(
                '/api/maintenance/hpm/upgradestatus?COMPONENT_ID=1')
            if status < 200 or status >= 300:
                raise Exception(rsp)
            percent = rsp['PROGRESS']
            if progress:
                progress({
                    'phase': 'apply',
                    'progress': .5 * percent})
            if percent < 100:
                time.sleep(3)
        if progress:
            progress({'phase': 'validating', 'progress': 0.0})
        del payload['SECTION_FLASH']
        rsp, status = wc.grab_json_response_with_status(
            '/api/maintenance/hpm/verifyimage', payload, method='PUT')
        percent = 0
        while percent < 100:
            rsp, status = wc.grab_json_response_with_status(
                '/api/maintenance/hpm/verifyimagestatus?COMPONENT_ID=1')
            if status < 200 or status >= 300:
                raise Exception(rsp)
            percent = rsp['PROGRESS']
            if progress:
                progress({
                    'phase': 'validating', 
                    'progress': 0.5 * percent})
            if percent < 100:
                time.sleep(3)
        rsp, status = wc.grab_json_response_with_status(
            '/api/maintenance/hpm/exitupdatemode', {'FWUPDATEID': uid},
            method='PUT')
        fu = webclient.FileUploader(wc, '/api/maintenance/firmware/firmware',
                                   'blob', hpminfo[1].combo_image, 'fwimage')
        fu.start()
        while fu.isAlive():
            fu.join(3)
            if progress:
                progress({
                    'phase': 'upload',
                    'progress': 50 * wc.get_upload_progress() + 50})
        rsp = wc.grab_json_response('/api/maintenance/firmware/verification')
        upgradeparms = {
            'preserve_config': 1,
            'flash_status': 1,
        }
        rsp, status = wc.grab_json_response_with_status(
            '/api/maintenance/firmware/upgrade',
            upgradeparms, method='PUT')
        if progress:
            progress({'phase': 'apply', 'progress': 50.0})
        applied = False
        while not applied:
            rsp = wc.grab_json_response(
                '/api/maintenance/firmware/flash-progress')
            percent = float(rsp['progress'].split('%')[0])
            percent = percent * 0.5 + 50
            if progress:
                progress({'phase': 'apply', 'progress': percent})
            if rsp['progress'] == '100% done' and rsp['state'] == 0:
                applied = True
                break
            time.sleep(3)
        hdrs = wc.stdheaders.copy()
        hdrs['Content-Length'] = 0
        rsp = wc.grab_json_response_with_status('/api/maintenance/reset', method='POST', headers=hdrs)
        return 'complete'
