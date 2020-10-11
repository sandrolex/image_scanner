from registry import Registry
import requests_async as arequests
import time
import asyncio
import random

url = 'https://lobs.local'
user = 'testuser'
passwd = 'testpassword'


#print(r._tags)


def chunks(list, n):
        for i in range(0, len(list), n):
            yield list[i:i+n]

async def scanImageFromQueue(queue, port):
    #ports = [5010, 5011, 5012, 5013]
    #port = ports[random.randint(0,3)]
    session = arequests.Session()
    for q in queue:
        print(".... request for " + str(port) + ' ' + q )
        session = arequests.Session()
        url = 'http://lobs.local:' + str(port) + '/xxx'
        payload = { 'image': q}
        res = await session.post(url, data=payload)
        if res.status_code != 200:
            print("error " + url)
            print(res.status_code)

async def runScanImages(tags, qtde_workers):
    ports = [5010, 5011, 5012, 5013]
    queue_size = len(tags) // qtde_workers
    workers = list(chunks(tags, queue_size))
    print(workers)
    #await asyncio.gather(*(scanImageFromQueue(n) for n in workers))
    await asyncio.gather(*(scanImageFromQueue(n, p) for n, p in zip(workers, ports)))


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
asyncio.run(runScanImages(tag_list, 3))
elapsed = time.perf_counter() - s
print(f"{elapsed:0.2f} seconds")

