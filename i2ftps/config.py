#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author: i2cy(i2cy@outlook.com)
# Project: I2FTPServer
# Filename: config
# Created on: 2022/5/12


import json
import os


class Config(object):

    def __init__(self, filename=None):

        if os.name == "nt":
            default_root = r"C:/i2ftp"
        else:
            default_root = "/usr/share/i2ftp"

        self.ftp_root = "{}/root".format(default_root)  # FTP 根目录
        self.tls_enabled = False  # 启用I2TCP的传输层加密
        self.keychain = b"&90%]>__AdfI2FTP$F%_+@$^:aBasicKey%_+@-$^:>"  # 密钥
        self.read_only = False  # 服务器是否只读
        self.port = 26842  # 端口
        self.log_file = "{}}/i2ftp.log".format(default_root)  # 日志文件
        self.log_level = "DEBUG"  # 日志等级（DEBUG、INFO、WARNING、ERROR、CRITICAL）

        if filename is not None:
            self.load(filename)

    def dump(self, filename):
        configs = {"root": self.ftp_root,
                   "port": self.port,
                   "log_file": self.log_file,
                   "log_level": self.log_level,
                   "keychain": self.keychain,
                   "tls": self.tls_enabled,
                   "read_only": self.read_only}

        with open(filename, "w") as f:
            json.dump(configs, f, indent=2)
            f.close()

    def load(self, filename):
        with open(filename, "w") as f:
            configs = json.load(f)
            f.close()
        self.ftp_root = configs["root"]
        self.port = configs["port"]
        self.tls_enabled = configs["tls"]
        self.read_only = configs["read_only"]
        self.keychain = configs["keychain"]


def main():
    print("Welcome to I2FTP Server Configurator [by I2cy]\n")
    print("this wizard will guide you to install I2FTP server"
          " or just generate a configuration file if you like")

    steps = 8

    config = Config()

    # 设置传输目录根地址
    root = None
    while root is None:
        root = input("step 1/{}: Set the root path of I2FTP to share with\n"
                     "(input nothing for default: {})".format(steps, config.ftp_root))
        if not root:
            root = config.ftp_root

        try:
            os.makedirs(root)
        except Exception as err:
            print("error: {}".format(err))
            root = None

    # 设置端口
    port = None
    while port is None:
        port = input("step 2/{}: Set the port number of server to listen on\n"
                     "(input nothing for default: {})".format(steps, config.port))
        if not port:
            port = config.port

        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise Exception("port must be greater than 0 and smaller than 65536")
        except Exception as err:
            print("error: {}".format(err))
            port = None

    # 设置密钥
    key = None
    while key is None:
        key = input("step 3/{}: Set the token for server to authentication\n"
                    "(input nothing for default: {})".format(steps, config.keychain.decode()))
        if not key:
            key = config.keychain

        try:
            os.makedirs(key)
        except Exception as err:
            print("error: {}".format(err))
            key = None
