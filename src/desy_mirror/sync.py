import asyncio
import base64
from enum import Enum
from functools import wraps
import hashlib
import logging
from pathlib import Path
import xml.etree.ElementTree as ET

import pycurl
from rest_tools.client import ClientCredentialsAuth
from tornado.httpclient import AsyncHTTPClient, HTTPRequest

from .config import ENV


AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")

def setupCurl(c):
    c.setopt(c.CAPATH, '/etc/grid-security/certificates')
    if ENV.LOG_LEVEL.lower() == 'debug':
        c.setopt(c.VERBOSE, True)

XMLNS = {
    'd': 'DAV:',
    'ns1': 'http://srm.lbl.gov/StorageResourceManager',
    'ns2': 'http://www.dcache.org/2013/webdav', 
}


class DirObject(Enum):
    Directory = 1
    File = 2


def convert_checksum_from_dcache(checksum: str) -> str:
    """DCache returns a binary checksum, but we want the hex digest"""
    if checksum.startswith('sha-512='):
        checksum = checksum[8:]
    return base64.b64decode(checksum).hex()


def sha512sum(filename: Path, blocksize: int = 1024 * 1024 * 2) -> str:
    """
    Compute the SHA512 hash of the data in the specified file.
    
    2MB block size seems optimal on our ceph system.
    """
    h = hashlib.sha512()
    b = bytearray(blocksize)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda: f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()


__semaphore = asyncio.Semaphore(ENV.MAX_PARALLEL)

def connection_semaphore(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        async with __semaphore:
            return await func(*args, **kwargs)
    return wrapper


class Sync:
    def __init__(self):

        self.rc = ClientCredentialsAuth(
            address=ENV.DEST_HOST,
            token_url=ENV.OPENID_URL,
            client_id=ENV.OPENID_CLIENT_ID,
            client_secret=ENV.OPENID_CLIENT_SECRET,
            timeout=ENV.TIMEOUT_SECS,
            retries=ENV.RETRIES,
        )

        self.http_client = AsyncHTTPClient(max_clients=100, defaults={
            'allow_nonstandard_methods': True,
            'connect_timeout': 0,
            'prepare_curl_callback': setupCurl,
        })

    async def run(self):
        await self.sync_dir(Path(ENV.SRC_DIRECTORY))

    @connection_semaphore
    async def get_children(self, path):
        fullpath = Path(ENV.DEST_PREFIX) / path.lstrip('/')
        self.rc._get_token()
        token = self.rc.access_token
        headers = {
            'Authorization': f'bearer {token}',
            'Depth': '1',
        }
        body = b'<?xml version="1.0"?><propfind xmlns="DAV:"><allprop/></propfind>'
        req = HTTPRequest(
            method='PROPFIND',
            url=f'{ENV.DEST_HOST}{fullpath}',
            headers=headers,
            body=body,
        )
        ret = await self.http_client.fetch(req)

        content = ret.body.decode('utf-8')
        logging.debug(content)
        root = ET.fromstring(content)
        children = {}
        for e in root.findall('.//d:response', XMLNS):
            path = Path(e.find('./d:href', XMLNS).text)
            if path != fullpath:
                data = {'name': path.name, 'type': DirObject.Directory}
                proplist = e.findall('./d:propstat/d:prop', XMLNS)
                for props in proplist:
                    if len(props) > 5:
                        break
                else:
                    props = None
                if props:
                    isdir = props.find('./d:iscollection', XMLNS)
                    if isdir is not None and isdir.text == 'FALSE':
                        data['type'] = DirObject.File
                        size = props.find('./d:getcontentlength', XMLNS)
                        if size is not None:
                            data['size'] = int(size.text)
                        checksums = props.find('./ns2:Checksums', XMLNS)
                        if checksums is not None and checksums.text:
                            data['checksums'] = {
                                c.split('=',1)[0]: convert_checksum_from_dcache(c.split('=',1)[1])
                                for c in checksums.text.split(';')
                            }
                        locality = props.find('./ns1:FileLocality', XMLNS)
                        if locality is not None:
                            data['tape'] = 'ONLINE' not in locality.text
                children[path.name] = data

        return children

    @connection_semaphore
    async def get_file(self, path, timeout=1200):
        fullpath = Path(ENV.DEST_PREFIX) / path.lstrip('/')
        self.rc._get_token()
        token = self.rc.access_token
        headers = {
            'Authorization': f'bearer {token}',
        }
        with open(path, 'wb') as f:
            req = HTTPRequest(
                method='GET',
                url=f'{ENV.DEST_HOST}{fullpath}',
                headers=headers,
                request_timeout=timeout,
                streaming_callback=f.write,
            )
            await self.http_client.fetch(req)

    @connection_semaphore
    async def rmfile(self, path: str, timeout=600):
        logging.info('RMFILE %s', path)
        fullpath = Path(ENV.DEST_PREFIX) / path.lstrip('/')
        self.rc._get_token()
        token = self.rc.access_token
        headers = {
            'Authorization': f'bearer {token}',
        }
        req = HTTPRequest(
            method='DELETE',
            url=f'{ENV.DEST_HOST}{fullpath}',
            headers=headers,
            request_timeout=timeout,
        )
        await self.http_client.fetch(req)

    async def rmtree(self, path: Path, timeout=600):
        logging.info('RMTREE %s', path)
        ret = await self.get_children(str(path.parent))
        if path.name not in ret:
            logging.info("does not exist")
        elif ret[path.name]['type'] == DirObject.File:
            await self.rmfile(str(path))
        else:
            children = await self.get_children(str(path))
            async with asyncio.TaskGroup() as tg:
                for child in children.values():
                    if child['type'] == DirObject.File:
                        tg.create_task(self.rmfile(str(path / child['name'])))
                    else:
                        tg.create_task(self.rmtree(path / child['name']))
            await self.rmfile(str(path))

    @connection_semaphore
    async def mkdir(self, path, timeout=60):
        logging.info('MKDIR %s', path)
        fullpath = Path(ENV.DEST_PREFIX) / path.lstrip('/')
        self.rc._get_token()
        token = self.rc.access_token
        headers = {
            'Authorization': f'bearer {token}',
        }
        req = HTTPRequest(
            method='MKCOL',
            url=f'{ENV.DEST_HOST}{fullpath}',
            headers=headers,
            request_timeout=timeout,
        )
        await self.http_client.fetch(req)

    @connection_semaphore
    async def put_file(self, path, timeout=1200):
        """
        Uploads file to a tmp name first, checks the checksum, then
        moves it to the final location.
        """
        logging.info('PUT %s', path)
        fullpath = Path(ENV.DEST_PREFIX) / path.lstrip('/')
        uploadpath = fullpath.with_name('_upload_' + fullpath.name)
        self.rc._get_token()
        token = self.rc.access_token
        filesize = Path(path).stat(follow_symlinks=True).st_size
        headers = {
            'Authorization': f'bearer {token}',
            'Content-Length': str(filesize),
            'Want-Digest': 'SHA-512',
            'Expect': '100-continue',
        }

        with open(path, 'rb') as f:
            def seek(offset, _origin):
                try:
                    f.seek(offset)
                    return pycurl.SEEKFUNC_OK
                except Exception:
                    return pycurl.SEEKFUNC_FAIL
            def cb(c):
                setupCurl(c)
                if filesize >= 2000000000:
                    c.unsetopt(c.INFILESIZE)
                    c.setopt(c.INFILESIZE_LARGE, filesize)
                else:
                    c.setopt(c.INFILESIZE, filesize)
                c.setopt(c.READDATA, f)
                c.setopt(c.SEEKFUNCTION, seek)

            req = HTTPRequest(
                method='PUT',
                url=f'{ENV.DEST_HOST}{uploadpath}',
                headers=headers,
                request_timeout=timeout,
                prepare_curl_callback=cb,
            )
            ret = await self.http_client.fetch(req)

        checksum = ret.headers.get('Digest', None)
        expected_checksum = sha512sum(path)
        if checksum:
            # we got a checksum back, so compare that directly
            checksum = convert_checksum_from_dcache(checksum)
        else:
            # read back file, and run checksum manually
            logging.info("PUT %s - no checksum in headers, so get manually", path)
            hasher = hashlib.sha512()
            req = HTTPRequest(
                method='GET',
                url=f'{ENV.DEST_HOST}{uploadpath}',
                headers=headers,
                request_timeout=timeout,
                streaming_callback=hasher.update,
            )
            await self.http_client.fetch(req)
            checksum = hasher.hexdigest()

        if expected_checksum == checksum:
            logging.info("PUT %s complete - checksum successful!", path)
        else:
            logging.error('PUT %s - bad checksum. expected %s, but received %s', path, expected_checksum, checksum)
            raise RuntimeError('bad checksum!')

        self.rc._get_token()
        token = self.rc.access_token
        headers = {
            'Authorization': f'bearer {token}',
            'Destination': str(fullpath),
        }
        req = HTTPRequest(
            method='MOVE',
            url=f'{ENV.DEST_HOST}{uploadpath}',
            headers=headers,
            request_timeout=timeout,
            prepare_curl_callback=setupCurl,
        )
        await self.http_client.fetch(req)

    def get_local_children(self, path: Path):
        children = {}
        for p in path.iterdir():
            if p.name.startswith("Run") and '_' in p.name:
                logging.debug('skipping versioned run directory')
                continue
            data = {
                'name': p.name,
                'type': DirObject.Directory if p.is_dir() else DirObject.File,
            }
            if data['type'] == DirObject.File:
                data['size'] = p.stat(follow_symlinks=True).st_size
            children[p.name] = data
        return children

    async def sync_dir(self, path: Path):
        logging.info("SYNC %s", path)
        # check if dir exists
        ret = await self.get_children(str(path.parent))
        if path.name not in ret:
            await self.mkdir(str(path))
            children = {}
        else:
            children = await self.get_children(str(path))
        
        # check contents
        expected_children = self.get_local_children(path)
        logging.debug('expected children: %s', expected_children)
        logging.debug('actual children: %s', children)

        # delete prev failed uploads
        async with asyncio.TaskGroup() as tg:
            for name in sorted(children):
                if name.startswith('_upload_'):
                    tg.create_task(self.rmfile(str(path / name)))

        # now upload as necessary
        async with asyncio.TaskGroup() as tg:
            for name in sorted(expected_children):
                if name in children:
                    # verify size at least
                    e = expected_children[name]
                    c = children[name]
                    if e['type'] != c['type']:
                        logging.error('Bad type on %s', path / name)
                        await self.rmtree(str(path / name))
                    elif e['type'] == DirObject.File and e.get('size', -1) == c.get('size', -1):
                        logging.info('verified %s', path / name)
                        continue
                else:
                    logging.info('missing from dest: %s', path / name)

                if expected_children[name]['type'] == DirObject.Directory:
                    tg.create_task(self.sync_dir(path / name))
                else:
                    tg.create_task(self.put_file(str(path / name)))
