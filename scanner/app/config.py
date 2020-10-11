import json
import os, logging

class Config:
    def __init__(self, configPath):
        self._path = configPath
        self._data = {}
        self._defaultPort = 5000
        self._defaultLogLevel = logging.INFO
        self.load_config()
    
    def load_config(self):
        try:
            with open(self._path, "r") as read_file:
                data = json.load(read_file)
                self._data = data
                self.parseValues()
                
        except:
            logging.error("[CFG] Error opening config file " + self._path)

    def parseValues(self):
        if 'port' in self._data:
            self._data['port'] = int(self._data['port'])
        else:
            self._data['port'] == self._defaultPort
        
        if 'log_level' in self._data:
            if self._data['log_level'] == 'DEBUG':
                self._data['log_level'] = logging.DEBUG
            elif self._data['log_level'] == 'INFO':
                self._data['log_level'] = logging.INFO
            elif self._data['log_level'] == 'WARNING':
                self._data['log_level'] = logging.WARNING
            elif self._data['log_level'] == 'ERROR':
                self._data['log_level'] = logging.ERROR
            elif self._data['log_level'] == 'CRITICAL':
                self._data['log_level'] = logging.CRITICAL
            else:
                self._data['log_level'] = self._defaultLogLevel