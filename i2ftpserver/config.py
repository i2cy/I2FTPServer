#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author: i2cy(i2cy@outlook.com)
# Project: I2FTPServer
# Filename: config
# Created on: 2022/5/12


import json


class Config(object):

    def __init__(self, filename=None):

        self.ftp_root = "/usr/share/i2ftp/root"         # FTP 根目录
        self.tls_enabled = False                        # 启用I2TCP的传输层加密
        self.keychain = b""                             # 密钥
        self.upload_disabled = False                    # 禁用上传功能
        self.port = 26842                               # 端口
        self.log_file = "/usr/share/i2ftp/i2ftp.log"    # 日志文件
        self.log_level = "DEBUG"                        # 日志等级（DEBUG、INFO、WARNING、ERROR、CRITICAL）

        if filename is not None:
            self.load(filename)

    def dump(self, filename):
        configs = {"root":              self.ftp_root,
                   "port":              self.port,
                   "keychain":          self.keychain,
                   "tls":               self.tls_enabled,
                   "disable_upload":    self.upload_disabled,
                   "log_file":          self.log_file,
                   "log_level":         self.log_level}

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
        self.upload_disabled = configs["disable_upload"]
        self.keychain = configs["keychain"]
