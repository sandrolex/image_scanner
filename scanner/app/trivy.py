import os
import json
import time, logging
import asyncio
from aiofile import AIOFile


class Trivy():
    def __init__(self, tmpfs='/tmp', server='', user='', password='', reg_url='', reg_user='', reg_pass=''):
        self._tmpfs = tmpfs
        self._vulnsQueue = []
        if server != '':
            self._server = server
        else:
            self._server = None
        self._reg_url = None
        if reg_url != '':
            self._reg_url = reg_url
        self._reg_user = None
        if reg_user != '':
            self._reg_user = reg_user
        self._reg_pass = None
        if reg_pass != '':
            self._reg_pass = reg_pass
    
    async def scan(self, image, local=True):
        cmd = f"trivy client --remote {self._server} --quiet --format json  {image}"
        if not local:
            auth = f"TRIVY_USERNAME={self._reg_user} TRIVY_PASSWORD='{self._reg_pass}' TRIVY_AUTH_URL={self._reg_url} "
            cmd = auth +  cmd
            
        
        logging.debug("[TRY] going to run ... " + cmd)
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        enc = stdout.decode('utf-8')
        json_str = json.loads(enc)
        for v in json_str[0]['Vulnerabilities']:
            vuln = {
                'vulnId': v['VulnerabilityID'],
                'pkg': v['PkgName'],
                'version': v['InstalledVersion'],
                'severity': v['Severity'],
                'image': image,
                'target': json_str[0]['Target'],
                'flavor': json_str[0]['Type']
            }
            self._vulnsQueue.append(vuln)
        
        logging.info(f"[TRY] Done scaniing {image} found {len(self._vulnsQueue)} vulns")

        return self._vulnsQueue
        