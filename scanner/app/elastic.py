import requests_async as arequests
import asyncio
import json
import base64, logging, time, hashlib

class Elastic():
    def __init__(self, url, user, passwd, pkgsPath='xxx', vulnsPath='yyy'):
        self._url = url
        self._user = user
        self._passwd = passwd
        self._pkgPath = pkgsPath
        self._vulnPath = vulnsPath
        self.i = '[ES]'
    
    async def addVulnsFromQueue(self, image, vulns):
        headers = {'Content-Type': 'application/json'}
        session = arequests.Session()
        for idx in range(len(vulns)):
            id = self.createVulnId(vulns[idx])
            es_url = self._url + self._vulnPath + '/_doc/' + id
            logging.debug(f"{self.i} Going to inject vuln ({image}) {id}")
            res = await session.post(es_url, headers=headers, auth=(self._user, self._passwd), data=json.dumps(vulns[idx]))
            if res.status_code != 200 and res.status_code != 201:
                # TODO: implement retry
                print(es_url)
                print(json.dumps(vulns[idx]))
                print("error 09")
                print(res.status_code)
                print(res.text)
                quit()
            logging.debug(f"{self.i} ({res.status_code}) r: {id} {vulns[idx]['vulnId']} {vulns[idx]['version']}")
            
    async def runAddVulns(self, image, vulns, qtde_workers):
        queue_size = len(vulns) // qtde_workers
        workers = list(self.chunks(vulns, queue_size))

        await asyncio.gather(*(self.addVulnsFromQueue(image, n) for n in workers))

    def addVulns(self, image, vulns, qtde_workers):
        s = time.perf_counter()
        logging.debug(f"{self.i} going to add {len(vulns)} vulns to ES")
        logging.debug(f"{self.i} using {qtde_workers} workers")
        asyncio.run(self.runAddVulns(image, vulns, qtde_workers))
        elapsed = time.perf_counter() - s
        logging.debug(f"{self.i} Done vulns {elapsed:0.2f} seconds")
        
    
    async def addPkgsFromQueue(self, image, pkgs):
        session = arequests.Session()
        headers = {'Content-Type': 'application/json'}
        for idx in range(len(pkgs)):
            id = self.createPkgId(image, pkgs[idx])
            es_url = self._url + self._pkgPath + '/_doc/' + id
            payload = {
                'image': image,
                'pkg': pkgs[idx]['name'],
                'version': pkgs[idx]['version']
            }
            logging.debug(f"{self.i} Going to inject pkg ({image}) {id}")
            res = await session.post(es_url, headers=headers, auth=(self._user, self._passwd), data=json.dumps(payload))
            if res.status_code != 200 and res.status_code != 201:
                # TODO: implement retry
                print("error 07")
                quit()
            logging.debug(f"{self.i} ({res.status_code}) r: {id} {pkgs[idx]['name']} {pkgs[idx]['version']}")
            

    async def runAddPkgs(self, image, pkgs, qtde_workers):
        queue_size = len(pkgs) // qtde_workers
        workers = list(self.chunks(pkgs, queue_size))

        await asyncio.gather(*(self.addPkgsFromQueue(image, n) for n in workers))

    def addPkgs(self, image, pkgs, qtde_workers):
        s = time.perf_counter()
        logging.debug(f"{self.i} Going to add {len(pkgs)} pkgs to ES ....")
        logging.debug(f"{self.i} Using {qtde_workers} workers")
        asyncio.run(self.runAddPkgs(image, pkgs, qtde_workers))
        elapsed = time.perf_counter() - s
        logging.debug(f"{self.i} Done pkgs {elapsed:0.2f} seconds")
    
    async def addBulkPkgs(self, image, pkgs):
        session = arequests.Session()
        headers = {'Content-Type': 'application/json'}
        pkgs_url = self._url + self._pkgPath + '/_bulk?pretty&refresh'
        out = ''
        for l in pkgs['pkgs']:
            name = self.createHash(l['name'], l['version'])
            idx = {'index': {'_id': name}}
            out += json.dumps(idx) + '\n'
            l['index'] = name
            l['image'] = image
            l['flavor'] = pkgs['flavor']
            out += json.dumps(l) + '\n'

        res = await session.post(pkgs_url, headers=headers, data=out)
        if res.status_code != 200 and res.status_code != 201:
            logging.error(f"{self.i} Error writing pkgs for image {image}")
            return False
        
        logging.debug(f"{self.i} Done Writing pkgs in elastic for {image}")
        return True

    async def addBulkVulns(self, image, vulns):
        session = arequests.Session()
        headers = {'Content-Type': 'application/json'}
        pkgs_url = self._url + self._vulnPath + '/_bulk?pretty&refresh'
        out = ''
        for v in vulns:
            name = self.createHash(v['image'], v['vulnId'])
            idx = {'index': {'_id': name}}
            out += json.dumps(idx) + '\n'
            v['index'] = name
            out += json.dumps(v) + '\n'
    
        res = await session.post(pkgs_url, headers=headers, data=out)
        if res.status_code != 200 and res.status_code != 201:
            logging.error(f"{self.i} Error writing vulns for image {image}")
            return False
        
        logging.debug(f"{self.i} Done Writing vulns in elastic for {image}")
        return True


    def chunks(self, list, n):
        for i in range(0, len(list), n):
            yield list[i:i+n]


    def createPkgId(self, image, pkg):
        m = image + ':' + pkg['name'] + ':' + pkg['version']
        enc = m.encode('utf-8')
        b = base64.b64encode(enc)
        return b.decode('utf-8')

    def createVulnId(self, vuln):
        m = vuln['image'] + ':' + vuln['pkg'] + ':' + vuln['vulnId']
        enc = m.encode('utf-8')
        b = base64.b64encode(enc)
        return b.decode('utf-8')

    def createHash(self, a,b):
        tmp = a + ':' + b
        m = hashlib.sha256()
        m.update(tmp.encode('utf-8'))
        return m.hexdigest()