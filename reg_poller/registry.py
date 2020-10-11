import requests
import requests_async as arequests
import json
import time
import asyncio


class Registry:
    def __init__(self, url, user, passwd):
        self._url = url
        self._passwd = passwd
        self._user = user
        self._repos = []
        self._tags = []
        self._s = arequests.Session()
        self._ss = requests.Session()

    def getRepos(self):
        headers = {
            'Content-Type': 'application/json'
        }
        catalog_url = self._url + '/v2/_catalog'
        done = False

        res = self._ss.get(catalog_url, headers=headers, auth=(self._user, self._passwd))
        if res.status_code != 200:
            print("Error Registry getRepos error 01")
            print(res.status_code)
            print(res.text)
            quit()

        #print(f"({res.status_code}) r: " + catalog_url)
        self._repos = res.json()['repositories']

        while not done:
            # check if there is another page
            if 'Link' in res.headers:
                last_pos = res.headers['Link'].find('>')
                next_url = res.headers['Link'][1:last_pos]
                res = requests.get(next_url, headers=headers, auth=(self._user, self._passwd))
                if res.status_code != 200:
                    print("Error Registry getRepos 02")
                    quit()
                #print(f"({res.status_code}) r: " + next_url)
                self._repos.extend(res.json()['repositories'])
            else :
                done = True

    async def agetTagsFromQueue(self, queue):
        for repo in queue:
            tags_url = self._url + '/v2/' + repo + '/tags/list'
            headers = {'Content-Type': 'application/json'}
            res = await self._s.get(tags_url, headers=headers, auth=(self._user, self._passwd))
            if res.status_code != 200:
                print("Error Registry getTagsFromQueue 03")
                if res.status_code == 403:
                    print(res.status_code)
                    continue
                else: 
                    quit()
            #print(f"({res.status_code}) r: " + tags_url)
            r = { 
                'repo': repo, 
                'tags': res.json()['tags'] 
            }
            self._tags.append(r)

        
    async def runTags(self, qtde_workers):
        queue_size = len(self._repos) // qtde_workers
        workers = list(self.chunks(self._repos, queue_size))
        await asyncio.gather(*(self.agetTagsFromQueue(n) for n in workers))

    def getTags(self, qtde_workers):
        s = time.perf_counter()
        print("[REG] Going to get repos for " + self._url + " ...")
        print("[REG] Using 1 worker")
        self.getRepos()
        elapsed = time.perf_counter() - s
        size = len(self._repos)
        print(f"[REG] Done {size} repos for {self._url} in {elapsed:0.2f} seconds")

        s = time.perf_counter()
        print("[REG] Going to get tags for repo " + self._url + " ....")
        print(f"[REG] Using {qtde_workers} workers")
        asyncio.run(self.runTags(qtde_workers))
        elapsed = time.perf_counter() - s
        size = 0
        for idx in range(len(self._tags)):
            size += len(self._tags[idx]['tags'])
        print(f"[REG] Done getting {size} tags for {self._url} in {elapsed:0.2f} seconds")


    def chunks(self, list, n):
        for i in range(0, len(list), n):
            yield list[i:i+n]