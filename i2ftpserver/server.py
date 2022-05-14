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
import shutil
from i2cylib.network.I2TCP import Server
from i2cylib.utils.logger import Logger
from i2cylib.utils.path import path_fixer
from i2cylib.utils.bytes import random_keygen
from i2ftpserver.config import Config

TIMEOUT = 20
MAX_CONNECTIONS = 200
MAX_UPDOWN_SESSIONS = 500
MAX_CMD_QUEUE = 500
FILE_SESSION_TIMEOUT = 120
FULL_SPEED_TIMEOUT = 20


VERSION = "1.0"


class FileSession:

    def __init__(self, path, readonly=True):
        """
        file I/O session object

        :param path: Path like object
        :param readonly: bool, set session to readonly
        """
        if readonly:
            self.io = open(path, "rb")
        else:
            self.io = open(path, "rb+")
        self.readonly = readonly
        self.__sha256 = hashlib.sha256()
        self.size = os.path.getsize(path)
        self.__flag_sha256_available = False
        self.fp = 0
        self.__sha256_fp = 0
        self.__lock_io = False
        self.__last_io_ts = time.time()

    def seek(self, offset):
        """
        change current file pointer to given offset

        :param offset: int
        :return: None
        """
        if self.fp == offset:
            return

        if self.__lock_io:
            time.sleep(0.001)
        self.__lock_io = True
        self.__last_io_ts = time.time()

        self.fp = offset
        self.io.seek(offset)

        self.__lock_io = False

    def write(self, data):
        """
        write data to standard file I/O

        :param data: bytes
        :return: int, length
        """
        if self.__lock_io:
            time.sleep(0.001)
        self.__lock_io = True
        self.__last_io_ts = time.time()

        try:
            ret = self.io.write(data)
        except Exception as err:
            ret = 0

        self.fp += ret

        self.__lock_io = False
        return ret

    def read(self, length):
        """
        read data from standard file I/O

        :param length: int, max data length
        :return: bytes, data
        """
        if self.__lock_io:
            time.sleep(0.001)
        self.__lock_io = True
        self.__last_io_ts = time.time()

        ret = self.io.read(length)

        self.fp += len(ret)

        self.__lock_io = False
        return ret

    def calc_sha256(self, step=True, size=8192):
        """
        calculate file's sha256 sum value by step or instantly

        :param step: bool, calculate one step
        :param size: int, read size for one step
        :return: bool, calculation status (False for already done the calculation)
        """
        if self.__flag_sha256_available:
            return False
        if self.__lock_io:
            time.sleep(0.001)
        self.__lock_io = True
        self.io.seek(self.__sha256_fp)

        if step:
            data = self.io.read(size)
            length = len(data)
            if length < size:
                self.__flag_sha256_available = True
            self.__sha256_fp += length
            self.__sha256.update(data)
        else:
            while True:
                data = self.io.read(size)
                if not data:
                    break
                self.__sha256.update(data)
            self.__flag_sha256_available = True

        self.io.seek(self.fp)

        self.__lock_io = False

        return True

    def age(self):
        """
        return the time (s) of this session from the last interact

        :return: float, time in seconds
        """
        return time.time() - self.__last_io_ts

    def sha256(self):
        """
        return file's sha256 sum, if calculation is still in progress,
        status will be False

        :return: (bool status, hex_str sum)
        """
        self.__last_io_ts = time.time()
        if self.__flag_sha256_available:
            return True, self.__sha256.hexdigest()
        else:
            return False, None

    def close(self):
        """
        close session

        :return: None
        """
        self.io.close()


class I2ftpServer:

    def __init__(self, config):
        """
        I2FTP object

        :param config: i2ftpserver.Config
        """

        assert isinstance(config, Config)

        self.__header = "[I2FTP]"
        self.config = config
        self.__server = None
        self.logger = Logger(config.log_file,
                             level=config.log_level)
        self.root = pathlib.Path(config.ftp_root)
        if not self.root.is_absolute():
            self.logger.CRITICAL("{} [Init] root path has to be absolute path")
            raise Exception("root path in configuration has to be absolute path")
        if not self.root.exists():
            path_fixer(config.ftp_root)

        self.__flag_kill = False
        self.threads_running = {"loop": False,
                                "file_session_manage_loop": False}

        self.connections = []  # handler池
        self.__cmd_queue = queue.Queue(maxsize=MAX_CMD_QUEUE)  # 命令池

        self.__file_session = {}  # 文件会话池

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

            # 检查路径是否存在
            if not path.exists():
                return b"\x00,path requested does not exist"

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
            ret = b"\x01," + json.dumps(res).encode("utf-8")

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

            # 建立会话
            session = FileSession(path, readonly=True)

            session_id = random_keygen(16)
            while session_id in self.__file_session:
                session_id = random_keygen(16)

            self.__file_session.update({session_id: session})

            ret = b"\x01," + session_id

        elif cmd == b"DOWN":  # 通过会话下载文件
            # 分割指令
            session_id = payload[:16]
            fp = int().from_bytes(payload[17:], "little", signed=True)

            # 检查会话是否有效
            if session_id not in self.__file_session:
                return b"\x00,invalid session id quested"

            session = self.__file_session[session_id]
            assert isinstance(session, FileSession)

            # 下发数据
            session.seek(fp)
            data = session.read(8192)
            ret = b"\x01," + data

        elif cmd == b"PULF":  # 创建上传会话命令
            # 若服务器只读则拒绝
            if self.config.read_only:
                return b"\x00,read-only server"

            # 检查会话池是否已满
            if len(self.__file_session) >= MAX_UPDOWN_SESSIONS:
                return b"\x00,file session full on server"

            # 检查文件路径是否符合要求
            path = payload.decode("utf-8")
            status, ret = self.__check_path(path)
            if not status:
                return ret
            path = self.root.joinpath(path)

            # 检查路径是否是文件夹
            if path.is_dir():
                return b"\x00,path does not exist or target is a directory"

            # 若路径不存在则创建路径
            path_fixer(path.as_posix())

            # 建立会话
            session = FileSession(path, readonly=False)

            session_id = random_keygen(16)
            while session_id in self.__file_session:
                session_id = random_keygen(16)

            self.__file_session.update({session_id: session})

            ret = b"\x01," + session_id

        elif cmd == b"UPLD":  # 通过会话上传数据
            # 若服务器只读则拒绝
            if self.config.read_only:
                return b"\x00,read-only server"

            # 分割指令
            session_id = payload[:16]
            fp = int().from_bytes(payload[17:25], "little", signed=True)
            data = payload[26:]

            # 检查会话是否有效
            if session_id not in self.__file_session:
                return b"\x00,invalid session id quested"

            session = self.__file_session[session_id]
            assert isinstance(session, FileSession)

            # 检查会话是否是上传会话
            if session.readonly:
                return b"\x00,read-only session"

            # 储存数据
            session.seek(fp)
            fp += session.write(data)
            ret = b"\x01," + fp.to_bytes(8, "little", signed=True)

        elif cmd == b"CLOZ":  # 关闭会话命令
            session_id = payload

            # 检查会话是否有效
            if session_id not in self.__file_session:
                return b"\x00,invalid session id quested"

            session = self.__file_session[session_id]
            assert isinstance(session, FileSession)

            # 若会话为下载会话
            if session.readonly:
                status, sha256 = session.sha256()

                # 检查sha256值是否运算完毕
                if not status:
                    return b"\x00,session is still calculating file's sha256 sum"

                # 关闭会话
                session.close()
                ret = b"\x01," + sha256.encode("utf-8")

            # 若为上传会话
            else:
                # 关闭会话
                session.close()
                ret = b"\x01"

        elif cmd == b"FIOP":  # 文件操作命令
            # 若服务器只读则拒绝
            if self.config.read_only:
                return b"\x00,read-only server"

            # 分割命令
            command = payload[0]
            args = payload[2:].decode("utf-8")
            paths = args.split(",")

            # 检查文件路径是否符合要求
            for path in paths:
                path = payload.decode("utf-8")
                status, ret = self.__check_path(path)
                if not status:
                    return ret

            # 重命名
            if command == 0:
                path0 = self.root.joinpath(paths[0])
                path1 = self.root.joinpath(paths[1])

                # 检查路径是否存在
                if not path0.exists():
                    return b"\x00,path requested does not exist"
                if path1.exists():
                    return b"\x00,target name already exists"

                try:
                    os.rename(path0, path1)
                except Exception as err:
                    return b"\x00," + str(err).encode("utf-8")

            # 移动
            elif command == 1:
                path0 = self.root.joinpath(paths[0])
                path1 = self.root.joinpath(paths[1])

                # 检查路径是否存在
                if not path0.exists():
                    return b"\x00,path requested does not exist"
                if path1.exists():
                    return b"\x00,target path already exists"

                # 移动文件
                try:
                    shutil.move(path0, path1)
                except Exception as err:
                    return b"\x00," + str(err).encode("utf-8")

            # 复制
            elif command == 2:
                path0 = self.root.joinpath(paths[0])
                path1 = self.root.joinpath(paths[1])

                # 检查路径是否存在
                if not path0.exists():
                    return b"\x00,path requested does not exist"
                if path1.exists():
                    return b"\x00,target path already exists"

                # 复制文件、文件夹
                try:
                    if path0.is_file():
                        shutil.copyfile(path0, path1)
                    else:
                        shutil.copytree(path0, path1)
                except Exception as err:
                    return b"\x00," + str(err).encode("utf-8")

            # 删除
            elif command == 3:
                path0 = self.root.joinpath(paths[0])

                # 检查路径是否存在
                if not path0.exists():
                    return b"\x00,path requested does not exist"

                # 删除文件、文件夹
                try:
                    if path0.is_file():
                        os.remove(path0)
                    else:
                        shutil.rmtree(path0)
                except Exception as err:
                    return b"\x00," + str(err).encode("utf-8")

            # 创建文件夹
            elif command == 4:
                path0 = self.root.joinpath(paths[0])

                # 检查路径是否存在
                if path0.exists():
                    return b"\x00,target path already exists"

                # 创建文件夹
                try:
                    os.makedirs(path0)
                except Exception as err:
                    return b"\x00," + str(err).encode("utf-8")

            ret = b"\x01"

        return ret

    def __file_session_manage_loop(self):
        if self.threads_running["file_session_manage_loop"]:
            return
        self.threads_running["file_session_manage_loop"] = True

        full_speed_ts = time.time()

        while self.__flag_kill:
            for ele in self.__file_session.keys():
                session = self.__file_session[ele]
                assert isinstance(session, FileSession)

                if self.__flag_kill:
                    break

                # 自动关闭不活动的会话
                if session.age() > FILE_SESSION_TIMEOUT:
                    session.close()
                    self.__file_session.pop(ele)
                    continue

                # 计算会话文件的sha256校验和
                ret = session.calc_sha256(step=True)
                if ret:
                    full_speed_ts = time.time()

                if time.time() - full_speed_ts > FULL_SPEED_TIMEOUT:
                    time.sleep(0.01)

    def __loop(self):
        assert isinstance(self.__server, Server)
        if self.threads_running["loop"]:
            return
        self.threads_running["loop"] = True

        while self.__flag_kill:
            con = self.__server.get_connection()
            if con is not None:
                con.send(b"I2FTP " + VERSION.encode())
                self.connections.append(con)

        self.threads_running["loop"] = False
