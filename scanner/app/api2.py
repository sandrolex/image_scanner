from flask import Flask, request
from trivy import Trivy
from config import Config
from apackages import Packages
from elastic import Elastic
import time, logging, sys
import asyncio
import hashlib

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

    e = Elastic(
        conf._data['es_url'],
        conf._data['es_user'],
        conf._data['es_password'],
        conf._data['es_pkgs_path'],
        conf._data['es_vulns_path']
    )

    #image_path = conf._data['registry_url'] + '/' + image

    image_path = f"{image['registry']}/{image['repo']}:{image['tag']}"
    await p.pullImage(image)
    
    result = await asyncio.gather(
        p.getPkgs(image), 
        t.scan(image, local=True)
    )

    if push:
        xx = await asyncio.gather(
            e.addBulkPkgs(result[0]),
            e.addBulkVulns(result[1])
        )
 

@app.route('/scan', methods=['POST'])
def image_scan():
    s = time.perf_counter()
    if not 'registry' in request.form:
        raise ValueError
    if not 'repo' in request.form:
        raise ValueError
    if not 'tag' in request.form:
        raise ValueError

    reg = request.form['registry']
    repo = request.form['repo']
    tag = request.form['tag']
    image = {'registry': reg, 'repo': repo, 'tag': tag}
    push = False
    if 'push' in request.form:
        push = True
    asyncio.run(runParallel(image, push))
    
    elapsed = time.perf_counter() - s 
    logging.debug(f"[API] OK {image} {elapsed:0.2f} seconds")
    
    return "{}"

if __name__ == '__main__':
    port = conf._data['port']
    app.run(debug=False, host='0.0.0.0', port=port)