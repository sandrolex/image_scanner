from registry import Registry
import requests_async as arequests
import time
import asyncio
import random
import requests



def chunks(list, n):
        for i in range(0, len(list), n):
            yield list[i:i+n]


async def runScanImages(tags, qtde_workers):
    ports = [5011, 5012, 5013, 5014]
    #ports = [5011, 5012]
    queue_size = len(tags) // qtde_workers
    workers = list(chunks(tags, queue_size))
    print(workers)
    await asyncio.gather(*(executeQueue(n, p) for n, p in zip(workers, ports)))
    #await asyncio.gather(*(executeQueue(n) for n in workers))


async def executeQueue(queue, port):
    session = arequests.Session()
    qtde = len(queue)
    count = 0
    for q in queue:
        ss = time.perf_counter()
        payload = {'image': q, 'push': 'true'}
        url = f"http://lobs.local:{port}/scan"
        res = await session.post(url, data=payload)
        if res.status_code != 200:
            print("error " + url)
            print(res.status_code)
            print(payload)
        count += 1
        ee = time.perf_counter() - ss
        print(f" DONE {port} {count}/{qtde} {q} {ee:0.2f} seconds")


reg = 'lobs.local'
url = 'https://' + reg
user = 'testuser'
passwd = 'testpassword'
r = Registry(url, user, passwd)
r.getTags(1)

print("START.....")
s = time.perf_counter()
tag_list = []
for repo in r._tags:
    for t in repo['tags']:
        elem = {
            'registry': reg,
            'repo': repo['repo'],
            'tag': t
        }
        #tag = repo['repo'] + ':' + t
        #tag_list.append(tag)
        tag_list.append(elem)
print(tag_list)

# first sequential
session = requests.Session()
qtde = len(tag_list)
count = 0
for t in tag_list:
    ss = time.perf_counter()
    print(f"going to scan {t} ...")
    #payload = {'image': t}
    payload = t
    payload['push'] = True
    res = session.post('http://localhost:5010/scan', data=payload)    
    print(res.status_code)
    ee = time.perf_counter() - ss
    count += 1
    print(f" DONE {count}/{qtde} {ee:0.2f} seconds")
    



#asyncio.run(runScanImages(tag_list, 4))
elapsed = time.perf_counter() - s
print(f"{elapsed:0.2f} seconds")

