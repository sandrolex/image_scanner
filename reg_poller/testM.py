from registry import Registry
import requests_async as arequests
import time
import asyncio
import random



def chunks(list, n):
        for i in range(0, len(list), n):
            yield list[i:i+n]

async def scanImageFromQueue(queue, port):
    session = arequests.Session()
    for q in queue:
        print(".... request for " + str(port) + ' ' + q )
        session = arequests.Session()
        url = 'http://lobs.local:' + str(port) + '/scan'
        payload = { 'image': q}
        res = await session.post(url, data=payload)
        if res.status_code != 200:
            print("error " + url)
            print(res.status_code)

async def runScanImages(tags, qtde_workers):
    ports = [5011, 5012]
    queue_size = len(tags) // qtde_workers
    workers = list(chunks(tags, queue_size))
    print(workers)
    await asyncio.gather(*(scanImageFromQueue(n, p) for n, p in zip(workers, ports)))


url = 'https://lobs.local'
user = 'testuser'
passwd = 'testpassword'
r = Registry(url, user, passwd)
r.getTags(1)

print("START.....")
s = time.perf_counter()
tag_list = []
for repo in r._tags:
    for t in repo['tags']:
        tag = repo['repo'] + ':' + t
        tag_list.append(tag)
print(tag_list)

asyncio.run(runScanImages(tag_list, 2))
elapsed = time.perf_counter() - s
print(f"{elapsed:0.2f} seconds")

