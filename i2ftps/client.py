#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author: i2cy(i2cy@outlook.com)
# Project: I2FTPServer
# Filename: client
# Created on: 2022/5/24

import os
import time
import json
import tqdm
import hashlib
from i2cylib.network import Client
from i2cylib.utils import Logger
from i2ftps.server import VERSION


class I2ftpClient:

    def __init__(self, hostname, key, port=26842, logger=None, max_buffer_size=1000):
        if logger is None:
            logger = Logger()
        self.logger = logger
        self.__clt = Client(hostname, port, key, logger=logger, max_buffer_size=max_buffer_size)

        self.__header = "[I2FTP]"
        self.version = b"I2FTP " + VERSION.encode("utf-8")

    def connect(self, timeout=10):
        ret = self.__clt.connect(timeout)
        version = self.__clt.get(timeout)
        if version != self.version:
            self.logger.ERROR("{} failed to match server version, server: {} client: {}".format(
                self.__header, version, self.version
            ))
            self.__clt.reset()
            ret = False
        return ret

    def list(self, path):

