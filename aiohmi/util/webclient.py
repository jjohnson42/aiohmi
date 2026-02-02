# Copyright 2015-2019 Lenovo
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

# This provides ability to do HTTPS in a manner like ssh host keys for the
# sake of typical internal management devices.  Compatibility back to python
# 2.6 as is found in commonly used enterprise linux distributions.

import asyncio
import base64
import copy
import gzip
import io
import json
import os
import socket
import ssl
import threading
import traceback

import aiohmi.exceptions as pygexc


import aiohttp
from aiohttp.cookiejar import CookieJar

import http.client as httplib
import http.cookies as Cookie

# Used as the separator for form data
BND = b'TbqbLUSn0QFjx9gxiQLtgBK4Zu6ehLqtLs4JOBS50EgxXJ2yoRMhTrmRXxO1lkoAQdZx16'

# We will frequently be dealing with the same data across many instances,
# consolidate forms to single memory location to get benefits..
uploadforms = {}

class CustomVerifier(aiohttp.Fingerprint):
    def __init__(self, verifycallback):
        self._certverify = verifycallback

    def check(self, transport):
        sslobj = transport.get_extra_info("ssl_object")
        cert = sslobj.getpeercert(binary_form=True)
        if not self._certverify(cert):
            transport.close()
            raise pygexc.UnrecognizedCertificate('Unknown certificate',
                                                 cert)

class FileUploader(threading.Thread):

    def __init__(self, webclient, url, filename, data=None, formname=None,
                 otherfields=(), formwrap=True, excepterror=True):
        self.wc = webclient
        self.url = url
        self.filename = filename
        self.data = data
        self.otherfields = otherfields
        self.formname = formname
        self.rsp = ''
        self.rspstatus = 500
        self.formwrap = formwrap
        self.excepterror = excepterror
        super(FileUploader, self).__init__()
        if not hasattr(self, 'isAlive'):
            self.isAlive = self.is_alive

    def run(self):
        try:
            self.rsp = self.wc.upload(
                self.url, self.filename, self.data, self.formname,
                otherfields=self.otherfields, formwrap=self.formwrap,
                excepterror=self.excepterror)
            self.rspstatus = self.wc.rspstatus
        except Exception:
            try:
                self.rspstatus = self.wc.rspstatus
            except Exception:
                pass
            raise
class Downloader:
    def __init__(self, filehandle):
        self.contentlen = None
        self._filehandle = filehandle
        self.dltask = None

    def get_progress(self):
        if self.contentlen is None:
            return -0.5
        return float(self._filehandle.tell()) / float(self.contentlen)
    
    async def join(self, timeout=None):
        if self.dltask is None:
            return
def make_downloader(webconn, url, dlfile):
        """
        Create a Downloader and start an asynchronous download task.

        This function immediately schedules the download to run in the
        background using asyncio.create_task(). Callers should perform any
        necessary setup (e.g., file preparation, callbacks) before invoking
        this function, and then use the returned Downloader instance to
        monitor progress or await completion via Downloader.join().
        """
            await self.dltask
        else:
            await asyncio.wait_for(self.dltask, timeout=timeout)

def make_downloader(webconn, url, dlfile):
        if isinstance(dlfile, str):
            dlfile = open(dlfile, 'wb')
        dler = Downloader(dlfile)
        dler.dltask = asyncio.create_task(download(webconn, url, dlfile, dler))
        return dler

async def download(webconn, url, dlfile, downloader):
    dlheaders = webconn.stdheaders.copy()
    if 'Accept-Encoding' in dlheaders:
        del dlheaders['Accept-Encoding']
    async with aiohttp.ClientSession(f'https://{webconn.host}:{webconn.port}', cookie_jar=webconn.cookies) as session:
        async with session.get(url, headers=dlheaders) as rsp:
            content_length = rsp.headers.get('content-length')
            try:
                downloader.contentlen = int(content_length) if content_length is not None else None
            except (TypeError, ValueError):
                downloader.contentlen = None
            async for chunk in rsp.content.iter_chunked(16384):
                dlfile.write(chunk)
    dlfile.close()
    

def get_upload_form(filename, data, formname, otherfields, boundary=BND):
    if not boundary:
        boundary = base64.urlsafe_b64encode(os.urandom(54))[:66] 
    ffilename = filename.split('/')[-1]
    if not formname:
        formname = ffilename
    try:
        return uploadforms[filename]
    except KeyError:
        try:
            data = data.read()
        except AttributeError:
            pass
        form = b''
        for ofield in otherfields:
            tfield = otherfields[ofield]
            xtra=''
            if isinstance(tfield, dict):
                tfield = json.dumps(tfield)
                xtra = '\r\nContent-Type: application/json'
            form += (b'--' + boundary
                     + '\r\nContent-Disposition: form-data; '
                       'name="{0}"{1}\r\n\r\n{2}\r\n'.format(
                           ofield, xtra, tfield).encode('utf-8'))
        form += (b'--' + boundary
                + '\r\nContent-Disposition: form-data; '
                  'name="{0}"; filename="{1}"\r\n'.format(
                      formname, ffilename).encode('utf-8'))
        form += b'Content-Type: application/octet-stream\r\n\r\n' + data
        form += b'\r\n--' + boundary + b'--\r\n'
        uploadforms[filename] = form, boundary
        return uploadforms[filename]


class WebConnection:
    def __init__(self, host, port, verifycallback=None):
        self.port = port
        if ':' in host:
            self.host = f'[{host}]'
        else:
            self.host = host
        if verifycallback:
            self.ssl = CustomVerifier(verifycallback)
        else:
            self.ssl = None
        self.verifycallback = verifycallback
        self.stdheaders = {}
        self.cookies = CookieJar(quote_cookie=False)

    def set_header(self, key, value):
        self.stdheaders[key] = value

    def dupe(self):
        newwc = WebConnection(self.host, self.port,
                              verifycallback=self.verifycallback)
        newwc.stdheaders = self.stdheaders.copy()
        newwc.cookies = CookieJar(quote_cookie=False)
        for cookie in self.cookies:
            newwc.cookies.update_cookies(
                {cookie.key: cookie.value}, response_url=f'https://{self.host}:{self.port}/')
        return newwc

    async def request(
            self, method, url, body=None, headers=None, referer=None):
        if headers is None:
            headers = self.stdheaders.copy()
        else:
            headers = headers.copy()
        if method == 'GET' and 'Content-Type' in headers:
            del headers['Content-Type']
        if method == 'POST' and body and 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if body and 'Content-Length' not in headers:
            headers['Content-Length'] = len(body)
        if referer:
            headers['referer'] = referer
        method = method.lower()
        async with aiohttp.ClientSession(
                f'https://{self.host}:{self.port}', cookie_jar=self.cookies) as session:
            thefunc = getattr(session, method)
            kwargs = {}
            if isinstance(body, dict):
                kwargs['json'] = body
            elif body:
                kwargs['data'] = body
            async with thefunc(url, headers=headers, ssl=self.ssl, **kwargs) as rsp:
                pass

    def set_basic_credentials(self, username, password):
        if isinstance(username, bytes) and not isinstance(username, str):
            username = username.decode('utf-8')
        if isinstance(password, bytes) and not isinstance(password, str):
            password = password.decode('utf-8')
        authinfo = ':'.join((username, password))
        if not isinstance(authinfo, bytes):
            authinfo = authinfo.encode('utf-8')
        authinfo = base64.b64encode(authinfo)
        if not isinstance(authinfo, str):
            authinfo = authinfo.decode('utf-8')
        self.stdheaders['Authorization'] = 'Basic {0}'.format(authinfo)

    async def grab_json_response(self, url, data=None, referer=None, headers=None):
        self.lastjsonerror = None
        body, status = await self.grab_json_response_with_status(
            url, data, referer, headers)
        if status == 200:
            return body
        self.lastjsonerror = body
        return {}

    async def grab_json_response_with_status(self, url, data=None, referer=None,
                                        headers=None, method=None):
        rsp, status, hdrs = await self.grab_response_with_status(url, data, referer, headers, method, expect_type='json')
        return rsp, status

    async def grab_response_with_status(self, url, data=None, referer=None,
                                        headers=None, method=None, expect_type=None):
        if not headers:
            headers = self.stdheaders.copy()
        else:
            headers = headers.copy()
        if referer:
            headers['referer'] = referer
        if not method:
            method = 'POST' if data is not None else 'GET'
        method = method.lower()
        if 'Content-Type' in headers and method.lower() in ('get', 'delete'):
            del headers['Content-Type']
        async with aiohttp.ClientSession(f'https://{self.host}:{self.port}', cookie_jar=self.cookies) as session:
            thefunc = getattr(session, method)
            kwargs = {}
            if isinstance(data, dict):
                kwargs['json'] = data
                if 'Content-Type' not in headers:
                    headers['Content-Type'] = 'application/json'
            elif data is not None:
                kwargs['data'] = data
            async with thefunc(url, headers=headers, ssl=self.ssl, **kwargs) as rsp:
                if rsp.status >= 200 and rsp.status < 300:
                    if expect_type == 'json':
                        return await rsp.json(content_type=''), rsp.status, rsp.headers
                    elif expect_type == 'text':
                        return await rsp.text(), rsp.status, rsp.headers
                    else:
                        return await rsp.read(), rsp.status, rsp.headers
                else:
                    return await rsp.read(), rsp.status, rsp.headers

    async def download(self, url, file):
        """Download a file to filename or file object

        """
        if isinstance(file, str):
            file = open(file, 'wb')
        dlheaders = self.stdheaders.copy()
        if 'Accept-Encoding' in dlheaders:
            del dlheaders['Accept-Encoding']
        async with aiohttp.ClientSession(f'https://{self.host}:{self.port}', cookie_jar=self.cookies) as session:
            async with session.get(url, headers=dlheaders) as rsp:
                self._currdl = rsp
                self._dlfile = file
                async for chunk in rsp.content.iter_chunked(16384):
                    file.write(chunk)
        self._currdl = None
        file.close()

    def get_download_progress(self):
        if not self._currdl:
            return None
        totalen = self._currdl.headers.get('content-length', None)
        if totalen is None:
            return -0.5
        return float(self._dlfile.tell()) / float(totalen)

