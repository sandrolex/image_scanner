import docker
import json
import logging, time


class Packages:
    def __init__(self, reg_url = '', user='', passwd=''):
        self._reg_url = reg_url
        self._user = user
        self._passwd = passwd
        self._flavor = None
        self._client = docker.from_env()
        self._lines = []
        self._state = []
        self.logged = []
        self.login()
    

    def login(self):
        try: 
            self._client.login(username=self._user, password=self._passwd, registry=self._reg_url)
            logging.debug("[PKG] Logged in successfully into registry")
        except:
            logging.error("[PKG] Error Packages.login 01")
            quit()

    def getFlavor(self, image):
        res = self._client.containers.run(image, 'cat /etc/os-release', entrypoint='')
        res_str = res.decode("utf-8")
        if 'Debian' in res_str or 'Ubuntu' in res_str:
            self._flavor = 'debian'
        elif 'CentOS' in res_str:
            self._flavor = 'centos'
        elif 'Alpine' in res_str:
            self._flavor = 'alpine'
        else:
            logging.error('[PKG] Error Packages.getFlavor 01')
            quit()
        logging.debug("[PKG] Found flavor: " + self._flavor)

    def pullImage(self, image):
        try:
            s = time.perf_counter()
            self._client.images.pull(image)
            elapsed = time.perf_counter() - s
            logging.debug("[PKG] Pulled image " + image + f"in {elapsed:0.2f} seconds")
        except:
            print("[PKG] Error Packages.pullImage 01")
            quit()

    ## TODO: check how to parse alpgine pkg version
    ## https://github.com/aquasecurity/trivy/blob/87ff0c1bbc9d99899c0edfd879deaee01df87ef2/pkg/scanner/utils/utils.go#L62
    def getAlpinePkgs(self, image):
        quit()
        try:
            res = self._client.containers.run(image, 'apk list', entrypoint='')
        except:
            logging.error("[PKG] Error Packages.getAlpinePkgs 01")
        
        packages = res.decode('utf-8')
        lines = packages.split('\n')
        pkgs = []
        for l in lines[:-1]:
            words = l.split()
            pkg = {'name': words[1], 'version': words[2]}
            pkgs.append(pkg)
        image = {
            'name': image,
            'pkgs': pkgs
        }
        self._state.append(image)


    def getDebianPkgs(self, image):
        try:
            res = self._client.containers.run(image, 'dpkg -l', entrypoint='')
        except:
            logging.error("[PKG] Error Packages.getDebianPkgs 01")
        
        packages = res.decode('utf-8')
        lines = packages.split('\n')
        pkgs = []
        for l in lines[5:-1]:
            words = l.split()
            pkg = {'name': words[1], 'version': words[2]}
            pkgs.append(pkg)
        image = {
            'name': image,
            'pkgs': pkgs
        }
        self._state.append(image)

    def getCentosPkgs(self, image):
        try:
            res = self._client.containers.run(image, 'yum list installed', entrypoint='')
        except:
            logging.error("[PKG] Error Pacakges.getCentosPkgs 01")
        packages = res.decode('utf-8')
        lines = packages.split('\n')
        pkgs = []
        for l in lines[2:-1]:
            words = l.split()
            pkg = {'name': words[0], 'version': words[1]}
            pkgs.append(pkg)
        image = {
            'name': image,
            'pkgs': pkgs
        }
        self._state.append(image)

    def getPkgs(self, image):
        endpoint = self._reg_url + '/' + image
        logging.info("[PKG] Pulling image: " + endpoint + " ...")
        s = time.perf_counter()
        self.pullImage(endpoint)
        elapsed = time.perf_counter() - s
        logging.info("[PKG] Done pulling " + endpoint + f" {elapsed:0.2f} seconds")

        logging.info("[PKG] Getting flavor ...")
        s = time.perf_counter()
        self.getFlavor(endpoint)
        elapsed = time.perf_counter() - s
        logging.info("[PKG] Done getting flavor" + f" {elapsed:0.2f} seconds")

        logging.info("[PKG] Getting package list ...")
        s = time.perf_counter()
        if self._flavor == 'debian':
            self.getDebianPkgs(endpoint)
        elif self._flavor == 'centos':
            self.getCentosPkgs(endpoint)
        else:
            logging.error("[PKG] Error Packages getPkgs 01")
            return False
        elapsed = time.perf_counter() - s
        logging.info("[PKG] done getPkgs " + image + f" {elapsed:0.2f} seconds")
        return True

    def remove(self, image):
        endpoint = self._reg_url + '/' + image
        try:
            logging.info("[PKG] Going to remove image " + image + " ...")
            s = time.perf_counter()
            self._client.images(endpoint)
        except docker.errors.ImageNotFound:
            logging.warning("[PKG] " + image + " Not Found")
            pass
        except:
            logging.error("[PKG] Error Packages.remove 01")
            quit()
        elapsed = time.perf_counter() - s
        logging.info("[PKG] Done removing " + image + f" {elapsed:0.2f} seconds")