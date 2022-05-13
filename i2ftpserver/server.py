#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author: i2cy(i2cy@outlook.com)
# Project: I2FTPServer
# Filename: server
# Created on: 2022/5/12


import threading
import queue
import time
import hashlib
import os
import pathlib
import json
from i2cylib.network.I2TCP import Server
from i2cylib.utils.logger import Logger
from i2cylib.utils.path import path_fixer
from i2cylib.utils.bytes import random_keygen
from i2ftpserver.config import Config


TIMEOUT = 20
MAX_CONNECTIONS = 200
MAX_UPDOWN_SESSIONS = 500
MAX_CMD_QUEUE = 500


class FileSession:

    def __init__(self, path):
        self.io = open(path, "rb+")
        self.sha256 = hashlib.sha256()
        self.size = os.path.getsize(path)
        self.__flag_sha256_avaliable = False
        self.__fp = 0
        self.__sha256_fp = 0
        self.__lock_io = False

    def seek(self, offset):
        if self.__lock_io:
            time.sleep(0.001)
        self.__lock_io = True

        self.__fp = offset
        self.io.seek(offset)

        self.__lock_io = False

    def calc_sha256(self, step=True):
        if self.__flag_sha256_avaliable:
            return
        if self.__lock_io:
            time.sleep(0.001)
        self.__lock_io = True

        if step:
            self.io.seek(self.__sha256_fp)
            data = self.io.read(4096)
            length = len(data)
            if length < 4096:
                self.__flag_sha256_avaliable = True
            self.__sha256_fp += length
            self.sha256.update(data)
            self.io.seek(self.__fp)
        else:
            self.io.seek(self.__sha256_fp)
            while True:
                data = self.io.read(4096)
                if not data:
                    break
                self.sha256.update(data)
            self.__flag_sha256_avaliable = True

        self.__lock_io = False




class I2ftpServer:

    def __init__(self, config):
        """
        I2FTP对象

        :param config: i2ftpserver.Config
        """

        assert isinstance(config, Config)

        self.__header = "[i2ftp]"
        self.config = config
        self.__server = None
        self.logger = Logger(config.log_file,
                             level=config.log_level)
        self.root = pathlib.Path(config.ftp_root)
        if not self.root.is_absolute():
            self.logger.CRITICAL("{} [init] root path has to be absolute path")
            raise Exception("root path in configuration has to be absolute path")
        if not self.root.exists():
            path_fixer(config.ftp_root)

        self.__flag_kill = False
        self.threads_running = {"loop": False,
                                "file_session_manage_loop": False}

        self.connections = []                                       # handler池
        self.__cmd_queue = queue.Queue(maxsize=MAX_CMD_QUEUE)       # 命令池
        # 文件会话对象储存格式：{<会话ID>:[最后活动的时间戳,
        #                             文件路径,
        #                             文件sha256对象,
        #                             文件大小,
        #                             最后一次sha256计算文件指针偏移量]}
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

    def __check_path(self, path):
        # 检查路径是否符合安全规定
        raw = path.replace("\\", "/").split("/")
        path = self.root.joinpath(path)

        if ".." in raw or not raw[0]:
            return False, b"\x00,requesting parent directory or using absolute path is not allowed"

        # 检查路径是否存在
        if not path.exists():
            return False, b"\x00,path requested does not exist"

        return True, b""

    def __process_requests(self, requests):
        assert isinstance(requests, bytes)
        requests = requests.split(b",", 1)
        cmd = requests[0]
        payload = requests[1]

        ret = b""

        if cmd == b"LIST":  # 查询命令
            res = {}
            path = payload.decode("utf-8")
            # 检查路径是否符合安全规定
            status, ret = self.__check_path(path)
            if not status:
                return ret
            path = self.root.joinpath(path)

            # 当路径是文件时
            if path.is_file():
                res.update({
                    path.name: {
                        "is_dir": False,
                        "size": os.path.getsize(path),
                        "time": os.path.getmtime(path)
                    }
                })

            # 当路径是目录时
            else:
                path = [ele for ele in path.glob("*")]
                for ele in path:
                    res.update({
                        ele.name: {
                            "is_dir": ele.is_dir(),
                            "size": os.path.getsize(ele),
                            "time": os.path.getmtime(ele)
                        }
                    })
            ret = json.dumps(res).encode("utf-8")

        elif cmd == b"GETF":  # 创建下载会话指令
            # 检查会话池是否已满
            if len(self.__file_session) >= MAX_UPDOWN_SESSIONS:
                return b"\x00,file session full on server"

            # 检查文件路径是否符合要求
            path = payload.decode("utf-8")
            status, ret = self.__check_path(path)
            if not status:
                return ret
            path = self.root.joinpath(path)

            # 检查文件是否存在且是文件
            if not path.exists() or path.is_dir():
                return b"\x00,path does not exist or target is a directory"

            session_id = random_keygen(64)
            session =

            self.__file_session.append(session)

        return ret

    def __file_session_manage_loop(self):
        if self.threads_running["file_session_manage_loop"]:
            return
        self.threads_running["file_session_manage_loop"] = True

        while self.__flag_kill:
            for ele in self.__file_session.keys():
                pass

    def __loop(self):
        assert isinstance(self.__server, Server)
        if self.threads_running["loop"]:
            return
        self.threads_running["loop"] = True

        while self.__flag_kill:
            con = self.__server.get_connection()
            if con is not None:
                self.connections.append(con)



        self.threads_running["loop"] = False

