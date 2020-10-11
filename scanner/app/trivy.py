import os
import json
import time, logging


class Trivy():
    def __init__(self, tmpfs='/tmp', server='', user='', password=''):
        self._tmpfs = tmpfs
        self._vulnsQueue = []
        if server != '':
            self._server = server
        else:
            self._server = None
    
    def scanImage(self, image):
        file_name = self._tmpfs + '/' + image.replace('/', '_').replace(':', '_') + '.json'
        s = time.perf_counter()
        logging.info("[TRY] Going to scan " + image + ' ... ')
        if self._server == None:
            res = os.system("trivy image -f json -o " + file_name + " " + image)
        else:
            res = os.system("trivy client --remote " + self._server + ' -f json -o ' + file_name + " " + image)
        if res != 0:
            logging.error("[TRY] Error Trivy.scanImage 01")
            return False

        with open(file_name) as json_file:
            data = json.load(json_file)
            for idx in range(len(data[0]['Vulnerabilities'])):
                vuln = {
                    'image': image,
                    'vulnId': data[0]['Vulnerabilities'][idx]['VulnerabilityID'],
                    'pkg': data[0]['Vulnerabilities'][idx]['PkgName'],
                    'version': data[0]['Vulnerabilities'][idx]['InstalledVersion'],
                    'severity': data[0]['Vulnerabilities'][idx]['Severity']
                    #'source': data[0]['Vulnerabilities'][idx]['SeveritySource']
                    #'vectors': data[0]['Vulnerabilities'][idx]['VendorVectors']
                }
                self._vulnsQueue.append(vuln)
        elapsed = time.perf_counter() - s
        logging.info(f"[TRY] done scanning {elapsed:0.2f} seconds")
        return True

