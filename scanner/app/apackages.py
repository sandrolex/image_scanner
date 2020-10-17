import docker
import aiodocker
import asyncio
import json
import logging, time
import base64
import random



class Packages:
    def __init__(self, reg_url = '', user='', passwd=''):
        self._reg_url = reg_url
        self._user = user
        self._passwd = passwd
        self._state = {}
        self.i = '[PKG]'
    

    async def initialize(self, image):
        if not image in self._state:
            self._state[image] = {}
            self._state[image]['client'] = aiodocker.Docker()
            self._state[image]['flavor'] = ''
            self._state[image]['pkgs'] = []
            self._state[image]['pulled'] = False
            logging.debug(f"{self.i} Initialized for image " + image)

    async def finalize(self, image):
        await self._state[image]['client'].close()
    
    async def createContainerId(self, image):
        enc = image.encode('utf-8')
        b = base64.b64encode(enc)
        id = b.decode('utf-8')[:8] + str(random.randint(99,9999))
        logging.debug(f"{self.i} Created Id {id} for {image}")
        return 
    
    def getAuth(self):
        a = self._user + ':' + self._passwd
        enc = base64.b64encode(a.encode('utf-8'))
        return enc.decode('utf-8')


    async def pullImage(self, image):
        if not image in self._state:
            await self.initialize(image)
        try:
            logging.debug(f"{self.i} Pulling image: {image} ...")
            s = time.perf_counter()
            token = self.getAuth()
            await self._state[image]['client'].images.pull(image, auth=token)
            elapsed = time.perf_counter() - s
            logging.debug(f"{self.i} Done pulling {image} in {elapsed:0.2f} seconds")
            self._state[image]['pulleld'] = True
        except aiodocker.DockerError as e:
            logging.error(f"{self.i} DockerError {e.status} {e.message}")
            logging.debug(f"{self.i} Error Packages.pullImage 01 {image}")
            raise e
        

    async def getFlavor(self, image):
        logging.debug(f"{self.i} Getting flavor for {image} ...")
        s = time.perf_counter()
            
        try:
            name = await self.createContainerId(image)
            container = await self._state[image]['client'].containers.create_or_replace(
                config={
                    'Cmd': ['cat', '/etc/os-release'],
                    'Image': image,
                    'Entrypoint': ''
                },
                name=name
            )
            await container.start()
            time.sleep(0.2)
            logs = await container.log(stdout=True)
            res_str = ''.join(logs)
            if 'Debian' in res_str or 'Ubuntu' in res_str:
                self._state[image]['flavor'] = 'debian'
            elif 'CentOS' in res_str:
                self._state[image]['flavor'] = 'centos'
            elif 'Alpine' in res_str:
                self._state[image]['flavor'] = 'alpine'
            else:
                raise Exception ('Unsupported OS type')
            
            elapsed = time.perf_counter() - s
            logging.debug(f"{self.i} Found flavor: {self._state[image]['flavor']} {image} {elapsed:0.2f} seconds")
            await container.stop()
            await container.delete()
        except Exception as e:
            logging.error(f"{self.i} {e.status} {e.message}")
            logging.debug(f"{self.i} Error Packages.getFlavor 02 {image}")
            raise e

    async def getDebianPkgs(self, image):
        try:
            name = await self.createContainerId(image)
            container = await self._state[image]['client'].containers.create_or_replace(
            config={
                'Cmd': ['dpkg', '-l'],
                'Image': image,
                'Entrypoint': ''
                },
                name=name
            )
            await container.start()
            time.sleep(0.2)
            logs = await container.log(stdout=True)
            res_str = ''.join(logs)
            lines = res_str.split('\n')
            pkgs = []
            for l in lines[5:-1]:
                words = l.split()
                pkg = {'name': words[1], 'version': words[2]}
                pkgs.append(pkg)
            
            self._state[image]['pkgs'] = pkgs
            await container.stop()
            await container.delete()

        except aiodocker.DockerError as e:
            logging.error(f"{self.i} DockerError {e.status} {e.message}")
            logging.debug(f"{self.i} Error Packages.getDebianPkgs 01")
            raise e

    async def getCentosPkgs(self, image):
        try:
            name = await self.createContainerId(image)
            container = await self._state[image]['client'].containers.create_or_replace(
            config={
                'Cmd': ['rpm', '-qa', '--queryformat', '%{NAME} %{VERSION}-%{RELEASE}\n'],
                'Image': image,
                'Entrypoint': ''    
                },
                name=name
            )
            await container.start()
            time.sleep(1)
            logs = await container.log(stdout=True)
            res_str = ''.join(logs)
            lines = res_str.split('\n')
            pkgs = []
            for l in lines[:-1]:
                words = l.split()
                pkg = {'name': words[0], 'version': words[1]}
                pkgs.append(pkg)
            
            self._state[image]['pkgs'] = pkgs
            await container.stop()
            await container.delete()
        except aiodocker.DockerError as e:
            logging.error(f"{self.i} DockerError {e.status} {e.message}")
            logging.error(f"{self.i} Error Packages.getCentosPkgs 01")
            raise e

    async def getPkgs(self, image):
        endpoint = self._reg_url + '/' + image
        await self.initialize(image)

        try:
            if not self._state[endpoint]['pulled']:
                await self.pullImage(endpoint)

            await self.getFlavor(endpoint)

            logging.info(f"{self.i} Getting package list for {endpoint} ...")
            s = time.perf_counter()
            if self._state[endpoint]['flavor'] == 'debian':
                await self.getDebianPkgs(endpoint)
            elif self._state[endpoint]['flavor'] == 'centos':
                await self.getCentosPkgs(endpoint)
            else:
                logging.error(f"{self.i} Error Packages getPkgs 01 {endpoint}")
            elapsed = time.perf_counter() - s
            logging.info(f"{self.i} Done getPkgs {endpoint} {elapsed:0.2f} seconds")
        except Exception as e:
            #logging.debug(f"{self.i} DockerError {e.status} {e.message}")
            logging.error(f"{self.i} Could not complete for image {endpoint}")


        await self.finalize(endpoint)
        return {
            'image': endpoint, 
            'pkgs': self._state[endpoint]['pkgs'],
            'flavor': self._state[endpoint]['flavor']
        }



#if __name__ == '__main__':
#    p = Packages('lobs.local', 'testuser', 'testpassword')
#    image = 'centos:7'
#    image2 = 'ubuntu:20.04'
    #image = 'lobs.local/ubuntu:20.04'
#    loop = asyncio.get_event_loop()
    #loop.run_until_complete(p.login())
    #loop.run_until_complete(p.pullImage(image))
    #loop.run_until_complete(p.getFlavor(image))
    #loop.run_until_complete(p.getCentosPkgs(image))
    #loop.run_until_complete(p.getDebianPkgs(image))
#    loop.run_until_complete(p.getPkgs(image))
#    loop.run_until_complete(p.getPkgs(image2))
#    loop.run_until_complete(p.close())
#    loop.close()
#    print(p._state)


    
   