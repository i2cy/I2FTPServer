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

    def __init__(self, hostname, key=b"&90%]>__AdfI2FTP$F%_+@$^:aBasicKey%_+@-$^:>",
                 port=26842, logger=None, max_buffer_size=1000, timeout=15):
        self.version = b"I2FTP " + VERSION.encode("utf-8")
        if logger is None:
            logger = Logger()
        self.logger = logger
        self.timeout = timeout
        self.__clt = Client(hostname, port, key, logger=logger, max_buffer_size=max_buffer_size)

        self.__header = "[I2FTP]"
        self.__flag_download_busy = False

    def __send_command(self, cmd):
        self.__clt.send(cmd)
        feed = self.__clt.get(timeout=self.timeout)

        status = False
        ret = ""

        if feed is not None:
            status, ret = feed.split(b",", 1)
            status = bool(status[0])

        if not status:
            ret = ret.decode("utf-8")

        return status, ret

    def connect(self, timeout=None):
        if timeout is None:
            timeout = self.timeout
        else:
            self.timeout = timeout
        ret = self.__clt.connect(timeout=timeout)
        version = self.__clt.get(timeout=timeout)
        if version != self.version:
            self.logger.ERROR("{} failed to match server version, server: {} client: {}".format(
                self.__header, version, self.version
            ))
            self.__clt.reset()
            ret = False
        return ret

    def disconnect(self):
        return self.__clt.reset()

    def list(self, path):
        cmd = "LIST,{}".format(path).encode("utf-8")

        status, ret = self.__send_command(cmd)

        if status:
            ret = ret.decode("utf-8")
            ret = json.loads(ret)

        return status, ret

    def download(self, request, verbose=True):
        cmd = "DOWN"


class DownloadSession:

    def __init__(self, upper, session_id, file_details):
        assert isinstance(upper, I2ftpClient)
        self.session_id = session_id
        self.__upper = upper
        self.details = file_details
        self.length = file_details["size"]

    def __len__(self):
        return self.length

    def __getitem__(self, item):
        if isinstance(item, slice):
            item.start

    def to_file(self, filename):



if __name__ == '__main__':
    test_server = "i2cy.tech"
    test_port = 26842
    test_key = b"&90%]>__AdfI2FTP$F%_+@$^:aBasicKey%_+@-$^:>"
    test_file = "small.mp4"
    test_log = "test.log"

    clt = I2ftpClient(test_server, test_key, test_port, logger=Logger(test_log, echo=False))

    clt.connect()
    print("test server connected")

    state, data = clt.list(".")
    print("<*> LIST test result: {}".format(state))
    print("    files under root: \n{}".format(json.dumps(data, indent=2)))

    clt.disconnect()
    print("disconnected from server")
    print("test ended")