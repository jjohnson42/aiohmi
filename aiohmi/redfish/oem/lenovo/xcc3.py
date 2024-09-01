import pyghmi.redfish.oem.generic as generic
import pyghmi.exceptions as pygexc


class OEMHandler(generic.OEMHandler):

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
                changeset[stg.replace('UEFI.' '')] = changeset[stg]
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

    def get_firmware_inventory(self, components, fishclient):
        fwlist = fishclient._do_web_request(fishclient._fwinventory)
        rawfwurls = [x['@odata.id'] for x in fwlist.get('Members', [])]
        fwurls = []
        for fwurl in rawfwurls:
            if fwurl.startswith('/redfish/v1/UpdateService/FirmwareInventory/Bundle.'):
                continue  # skip Bundle information for now
            fwurls.append(fwurl)
        self._fwnamemap = {}
        for res in fishclient._do_bulk_requests(fwurls):
            redres = res[0]
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
            if swid.startswith('FPGA-') or swid.startswith('UEFI-') or swid.startswith('BMC-'):
                buildid = swid.split('-')[1] + version.split('-')[0]
                version = '-'.join(version.split('-')[1:])
            if version:
                redres['Version'] = version
            cres = fishclient._extract_fwinfo(res)
            if cres[0] is None:
                continue
            if buildid:
                cres[1]['build'] = buildid
            yield cres
        raise pygexc.BypassGenericBehavior()


