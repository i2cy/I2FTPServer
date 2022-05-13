#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author: i2cy(i2cy@outlook.com)
# Project: I2FTPServer
# Filename: server
# Created on: 2022/5/12


import threading
import queue
import time
from i2cylib.network.I2TCP import Server
from i2cylib.utils.logger import Logger
from i2ftpserver.config import Config


TIMEOUT = 20
MAX_CONNECTIONS = 200
MAX_UPDOWN_SESSIONS = 500
MAX_CMD_QUEUE = 500


class I2ftpServer:

    def __init__(self, config):
        """
        I2FTP对象

        :param config: i2ftpserver.Config
        """

        assert isinstance(config, Config)

        self.config = config
        self.__server = None
        self.logger = Logger(config.log_file,
                             level=config.log_level)

        self.__flag_kill = False
        self.threads_running = {"loop": False,
                                "file_session_manage_loop": False}

        self.connections = []                                       # handler池
        self.__cmd_queue = queue.Queue(maxsize=MAX_CMD_QUEUE)       # 命令池
        self.__file_session = {}                                    # 文件会话池

    def start(self):
        """
        启动I2FTP服务器

        :return: None
        """
        self.__server = Server(key=self.config.keychain,
                               port=self.config.port,
                               logger=self.logger,
                               max_con=MAX_CONNECTIONS,
                               timeout=TIMEOUT,
                               secured_connection=self.config.tls_enabled
                               )
        self.__server.start()
        threading.Thread(target=self.__loop).start()
        threading.Thread(target=self.__file_session_manage_loop).start()

    def stop(self):
        """
        停止I2FTP服务器

        :return:
        """
        assert isinstance(self.__server, Server)
        self.__flag_kill = True
        keep = True
        while keep:
            time.sleep(0.02)
            keep = False
            for ele in self.threads_running.keys():
                if self.threads_running[ele]:
                    keep = True
                    break

        self.__server.kill()

    def __file_session_manage_loop(self):
        if self.threads_running["file_session_manage_loop"]:
            return
        self.threads_running["file_session_manage_loop"] = True

    def __loop(self):
        assert isinstance(self.__server, Server)
        if self.threads_running["loop"]:
            return
        self.threads_running["loop"] = True

        while self.__flag_kill:
            con = self.__server.get_connection()

        self.threads_running["loop"] = False

