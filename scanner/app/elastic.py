import requests_async as arequests
import asyncio
import json
import base64, logging, time

class Elastic():
    def __init__(self, url, user, passwd, pkgsPath='xxx', vulnsPath='yyy'):
        self._url = url
        self._user = user
        self._passwd = passwd
        self._pkgPath = pkgsPath
        self._vulnPath = vulnsPath
    
    async def addVulnsFromQueue(self, image, vulns):
        headers = {'Content-Type': 'application/json'}
        session = arequests.Session()
        for idx in range(len(vulns)):
            id = self.createVulnId(vulns[idx])
            es_url = self._url + self._vulnPath + '/_doc/' + id
            logging.debug("[ES] Going to inject vuln (" + image + ") " + id)
            res = await session.post(es_url, headers=headers, auth=(self._user, self._passwd), data=json.dumps(vulns[idx]))
            if res.status_code != 200 and res.status_code != 201:
                # TODO: implement retry
                print(es_url)
                print(json.dumps(vulns[idx]))
                print("error 09")
                print(res.status_code)
                print(res.text)
                quit()
            logging.debug(f"[ES] ({res.status_code}) r: " + id + ' ' + vulns[idx]['vulnId'] + ' ' + vulns[idx]['version'])
            
    async def runAddVulns(self, image, vulns, qtde_workers):
        queue_size = len(vulns) // qtde_workers
        workers = list(self.chunks(vulns, queue_size))

        await asyncio.gather(*(self.addVulnsFromQueue(image, n) for n in workers))

    def addVulns(self, image, vulns, qtde_workers):
        s = time.perf_counter()
        logging.info("[ES] going to add " + str(len(vulns)) + " vulns to ES")
        logging.info("[ES] using " + str(qtde_workers) + " workers")
        asyncio.run(self.runAddVulns(image, vulns, qtde_workers))
        elapsed = time.perf_counter() - s
        logging.info(f"[ES] Done vulns {elapsed:0.2f} seconds")
        
    
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
            logging.debug("[ES] Going to inject pkg (" + image + ") " + id)
            res = await session.post(es_url, headers=headers, auth=(self._user, self._passwd), data=json.dumps(payload))
            if res.status_code != 200 and res.status_code != 201:
                # TODO: implement retry
                print("error 07")
                quit()
            logging.debug(f"[ES] ({res.status_code}) r: " + id + ' ' + pkgs[idx]['name'] + ' ' + pkgs[idx]['version'])
            

    async def runAddPkgs(self, image, pkgs, qtde_workers):
        queue_size = len(pkgs) // qtde_workers
        workers = list(self.chunks(pkgs, queue_size))

        await asyncio.gather(*(self.addPkgsFromQueue(image, n) for n in workers))

    def addPkgs(self, image, pkgs, qtde_workers):
        s = time.perf_counter()
        logging.info("[ES] Going to add " + str(len(pkgs)) + " pkgs to ES ....")
        logging.info("[ES] Using " + str(qtde_workers) + " workers")
        asyncio.run(self.runAddPkgs(image, pkgs, qtde_workers))
        elapsed = time.perf_counter() - s
        logging.info(f"[ES] Done pkgs {elapsed:0.2f} seconds")
    

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
