#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author: i2cy(i2cy@outlook.com)
# Project: I2FTPServer
# Filename: server
# Created on: 2022/5/12

from i2cylib.network.I2TCP import Server


class I2ftpServer:

    def __init__(self, config_file):

        self.ftp_root = ""