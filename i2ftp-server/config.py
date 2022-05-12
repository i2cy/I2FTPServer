#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author: i2cy(i2cy@outlook.com)
# Project: I2FTPServer
# Filename: config
# Created on: 2022/5/12


import json


class Config(object):

    def __init__(self, filename=None):

        self.ftp_root = ""              # FTP 根目录
        self.tls_enabled = False        # 启用I2TCP的传输层加密
        self.keychain = b""             # 密钥
        self.upload_disabled = False     # 禁用上传功能

        if filename is not None:
            self.load(filename)

    def dump(self, filename):
        configs = {"root":              self.ftp_root,
                   "keychain":          self.keychain,
                   "tls":               self.tls_enabled,
                   "disable_upload":    self.upload_disabled}

        with open(filename, "w") as f:
            json.dump(configs, f, indent=2)
            f.close()

    def load(self, filename):
        with open(filename, "w") as f:
            configs = json.load(f)
            f.close()
        self.ftp_root = configs["root"]
        self.tls_enabled = configs["tls"]
        self.upload_disabled = configs["disable_upload"]
        self.keychain = configs["keychain"]
