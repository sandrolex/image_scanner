from flask import Flask, request
from trivy import Trivy
from config import Config
from apackages import Packages
from elastic import Elastic
import time, logging, sys
import asyncio
import json
import base64
import hashlib
import requests

def configure_logging(level):
    logging.basicConfig(
        stream=sys.stdout,
        format='%(asctime)s %(levelname)s  : %(message)s',
        level=level
    )

conf = Config('../conf/scanner.json')

configure_logging(conf._data['log_level'])



vulns = {}
app = Flask(__name__)

async def runParallel(image, push=False):
    p = Packages(
        reg_url=conf._data['registry_url'],
        user=conf._data['registry_user'],
        passwd=conf._data['registry_password']
    )

    t = Trivy(
        server=conf._data['trivy_url'],
        reg_url = conf._data['registry_url'],
        reg_user = conf._data['registry_user'],
        reg_pass = conf._data['registry_password']
    )

    dst = conf._data['registry_url'] + '/' + image

    await p.pullImage(dst)
    result = await asyncio.gather(p.getPkgs(image), t.scan(dst, local=True))

    if not push:
        return

    pkgs_url = 'http://lobs.local:9200/pkgs/_bulk?pretty&refresh'
    headers = {'Content-Type': 'application/json'}
    out = ''
    for l in result[0]['pkgs']:
        name = createHash(l['name'], l['version'])
        idx = {'index': {'_id': name}}
        out += json.dumps(idx) + '\n'
        l['index'] = name
        l['image'] = dst
        l['flavor'] = result[0]['flavor']
        out += json.dumps(l) + '\n'
    res = requests.post(pkgs_url, headers=headers, data=out)
    if res.status_code != 200 and res.status_code != 201:
        print(res.status_code)
        print(res.text)
        print("ERROR PKGS")
    else:
        print("UPDATED PKGS")


    vulns_url = 'http://lobs.local:9200/vulns/_bulk?pretty&refresh'
    headers = {'Content-Type': 'application/json'}
    out = ''
    for v in result[1]:
        name = createHash(v['image'], v['vulnId'])
        idx = {'index': {'_id': name}}
        out += json.dumps(idx) + '\n'
        v['index'] = name
        out += json.dumps(v) + '\n'
    res = requests.post(vulns_url, headers=headers, data=out)
    if res.status_code != 200 and res.status_code != 201:
        print("ERROR PKGS")
    else:
        print("UPDATED PKGS")
 
def createHash(a,b):
    tmp = a + ':' + b
    m = hashlib.sha256()
    m.update(tmp.encode('utf-8'))
    return m.hexdigest()

def createName(a, b):
    tmp = a + ':' + b
    enc = tmp.encode('utf-8')
    b = base64.b64encode(enc)
    return b.decode('utf-8')

@app.route('/scan', methods=['POST'])
def image_scan():
    s = time.perf_counter()
    image = request.form['image']
    push = False
    if 'push' in request.form:
        push = True
    asyncio.run(runParallel(image, push))
    
    elapsed = time.perf_counter() - s 
    logging.info(f"[API] OK {image} {elapsed:0.2f} seconds")
    
    #total_v = len(t._vulnsQueue)
    #total_p = len(p._state[0]['pkgs'])
    th=0
    tm=0
    tl=0
    tu = 0
    #for v in t._vulnsQueue:
    #    if v['severity'].lower() == 'high':
    #        th += 1
    #    elif v['severity'].lower() == 'medium':
    #        tm += 1
    #    elif v['severity'].lower() == 'low':
    #        tl += 1
    #    else:
    #        tu += 0
        
    #out = {
    #    'image': image, 
    #    'pkgs': total_p,
    #    'vulns': {
    #        'total': total_v,
    #        'high': th,
    #        'medium': tm,
    #        'low': tl,
    #        'unknown': tu
    #    }
    #}

    #t._vulnsQueue = []
    #p._state = []
    
    #return out
    return "{}"

if __name__ == '__main__':
    port = conf._data['port']
    app.run(debug=False, host='0.0.0.0', port=port)