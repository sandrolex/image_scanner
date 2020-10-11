from flask import Flask, request
from trivy import Trivy
from config import Config
from packages import Packages
from elastic import Elastic
import time, logging, sys

def configure_logging(level):
    logging.basicConfig(
        stream=sys.stdout,
        format='%(asctime)s %(levelname)s  : %(message)s',
        level=level
    )

conf = Config('../conf/scanner.json')

configure_logging(conf._data['log_level'])

p = Packages(
    reg_url=conf._data['registry_url'],
    user=conf._data['registry_user'],
    passwd=conf._data['registry_password']
)

t = Trivy(server=conf._data['trivy_url'])

e = Elastic(
    conf._data['es_url'], 
    conf._data['es_user'],
    conf._data['es_password'],
    pkgsPath=conf._data['es_pkgs_path'],
    vulnsPath=conf._data['es_vulns_path']
)

vulns = {}
app = Flask(__name__)

@app.route('/scan', methods=['POST'])
def image_scan():
    s = time.perf_counter()
    image = request.form['image']

    if not p.getPkgs(image):
        logging.error("[API] Error Api 01")
        quit()
    dst = conf._data['registry_url'] + '/' + image
    if not t.scanImage(dst):
        logging.error("[API] Error scanning Image")
        quit()
    
    e.addVulns(image, t._vulnsQueue, conf._data['es_vulns_workers'])
    e.addPkgs(image, p._state[0]['pkgs'], conf._data['es_pkgs_workers'])
    elapsed = time.perf_counter() - s 
    logging.info(f"[API] OK {image} {elapsed:0.2f} seconds")
    
    total_v = len(t._vulnsQueue)
    total_p = len(p._state[0]['pkgs'])
    th=0
    tm=0
    tl=0
    tu = 0
    for v in t._vulnsQueue:
        if v['severity'].lower() == 'high':
            th += 1
        elif v['severity'].lower() == 'medium':
            tm += 1
        elif v['severity'].lower() == 'low':
            tl += 1
        else:
            tu += 0
        
    out = {
        'image': image, 
        'pkgs': total_p,
        'vulns': {
            'total': total_v,
            'high': th,
            'medium': tm,
            'low': tl,
            'unknown': tu
        }
    }

    return out

if __name__ == '__main__':
    port = conf._data['port']
    app.run(debug=False, host='0.0.0.0', port=port)