#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author: i2cy(i2cy@outlook.com)
# Project: I2FTPServer
# Filename: server
# Created on: 2022/5/12


import threading
from i2cylib.network.I2TCP import Server
from i2cylib.utils.logger import Logger
from i2ftpserver.config import Config


class I2ftpServer:

    def __init__(self, config):

        assert isinstance(config, Config)

        self.config = config
        self.__server = None
        self.logger = Logger(config.log_file,
                             level=config.log_level)

        self.__flag_kill = False
        self.threads_running = {"loop": False}
        self.connections = []

    def start(self):
        self.__server = Server(key=self.config.keychain,
                               port=self.config.port,
                               logger=self.logger,
                               max_con=200,
                               secured_connection=self.config.tls_enabled
                               )
        self.__server.start()
        threading.Thread(target=self.__loop).start()

    def __loop(self):
        assert isinstance(self.__server, Server)
        if self.threads_running["loop"]:
            return
        self.threads_running["loop"] = True

        while self.__flag_kill:
            con = self.__server.get_connection()
