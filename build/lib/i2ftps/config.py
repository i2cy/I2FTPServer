#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author: i2cy(i2cy@outlook.com)
# Project: I2FTPServer
# Filename: config
# Created on: 2022/5/12


import json
import os
import pathlib
from i2cylib.utils.path import path_fixer
from i2cylib.utils.bytes import random_keygen


class Config(object):

    def __init__(self, filename=None):
        default_root = pathlib.Path.home().joinpath("i2ftp").as_posix()

        self.ftp_root = "{}/root".format(default_root)  # FTP 根目录
        self.tls_enabled = False  # 启用I2TCP的传输层加密
        self.keychain = b"&90%]>__AdfI2FTP$F%_+@$^:aBasicKey%_+@-$^:>"  # 密钥
        self.read_only = False  # 服务器是否只读
        self.port = 26842  # 端口
        self.log_file = "{}/i2ftp.log".format(default_root)  # 日志文件
        self.log_level = "INFO"  # 日志等级（DEBUG、INFO、WARNING、ERROR、CRITICAL）

        if filename is not None:
            self.load(filename)

    def dump(self, filename):
        configs = {"root": self.ftp_root,
                   "port": self.port,
                   "log_file": self.log_file,
                   "log_level": self.log_level,
                   "keychain": self.keychain.hex(),
                   "tls": self.tls_enabled,
                   "read_only": self.read_only}

        with open(filename, "w") as f:
            json.dump(configs, f, indent=2)
            f.close()

    def load(self, filename):
        with open(filename, "r") as f:
            configs = json.load(f)
            f.close()
        self.ftp_root = configs["root"]
        self.port = configs["port"]
        self.tls_enabled = configs["tls"]
        self.read_only = configs["read_only"]
        self.keychain = bytes.fromhex(configs["keychain"])
        self.log_level = configs["log_level"]
        self.log_file = configs["log_file"]


def generate_systemd(config_filename, addon=None):
    if addon is None or addon == 1:
        addon = ""
    curren_user = os.getlogin()
    text = """[Unit]
Description=I2FTP Server Service
After=network.target

[Service]
Type=simple
DynamicUser=false
Group={}
User={}
Restart=Always
RestartSec=20s
ExecStart=/usr/local/bin/i2ftps -c \"{}\" start
ExecStop=/usr/local/bin/i2ftps -c \"{}\" stop
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
Alias=i2ftps{}.service
""".format(curren_user, curren_user, config_filename, config_filename, addon)

    return text


def main():
    print("Welcome to I2FTP Server Configurator [by I2cy]\n")
    print("this wizard will guide you to install I2FTP server"
          " or just generate a configuration file if you like."
          "\nNotice: you can always run this wizard by command "
          "\"i2ftps-setup\"")

    steps = 9
    if os.name == "nt":
        steps -= 1

    config = Config()

    # 设置传输目录根地址
    root = None
    while root is None:
        root = input("step 1/{}: Set the root path of I2FTP to share with\n"
                     "(input nothing for default: {}): ".format(steps, config.ftp_root))
        if not root:
            root = config.ftp_root

        try:
            if not os.path.exists(root):
                os.makedirs(root)
        except Exception as err:
            print("error: {}".format(err))
            root = None

    config.ftp_root = root

    # 设置端口
    port = None
    while port is None:
        port = input("step 2/{}: Set the port number of server to listen on\n"
                     "(input nothing for default: {}): ".format(steps, config.port))
        if not port:
            port = config.port

        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise Exception("port must be greater than 0 and smaller than 65536")
        except Exception as err:
            print("error: {}".format(err))
            port = None

    config.port = port

    # 设置密钥
    key = None
    while key is None:
        key = input("step 3/{}: Set the token for server to authentication\n"
                    "(input nothing for default: \"{}\"): ".format(steps, config.keychain.decode()))
        if not key:
            key = config.keychain.decode()

        try:
            key = key.encode()
        except Exception as err:
            print("error: {}".format(err))
            key = None

    config.keychain = key

    # 设置日志文件
    log_file = None
    while log_file is None:
        log_file = input("step 4/{}: Set log's filename\n"
                         "(input nothing for default: {}): ".format(steps, config.log_file))
        if not log_file:
            log_file = config.log_file

        try:
            path_fixer(log_file)
        except Exception as err:
            print("error: {}".format(err))
            log_file = None

    config.log_file = log_file

    # 设置日志等级
    log_level = None
    while log_level is None:
        log_level = input("step 5/{}: Set logging level (DEBUG、INFO、WARNING、ERROR、CRITICAL)\n"
                          "(input nothing for default: {}): ".format(steps, config.log_level))
        if not log_level:
            log_level = config.log_level

        try:
            log_level = log_level.upper()
            if log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
                raise Exception("logging level must be selected from DEBUG, INFO, WARNING, ERROR or CRITICAL")
        except Exception as err:
            print("error: {}".format(err))
            log_level = None

    config.log_level = log_level

    # 设置服务器是否只读
    readonly = None
    while readonly is None:
        readonly = input("step 6/{}: Read-Only server? (Y/N)\n"
                         "(input nothing for default: {}): ".format(steps, config.read_only))

        if readonly:
            if readonly in ("y", "Y", "Yes", "yes"):
                readonly = True
            else:
                readonly = False

        else:
            readonly = config.read_only

    config.read_only = readonly

    # 设置服务器是否加密
    tls = None
    while tls is None:
        tls = input("step 7/{}: Use TLS? (Y/N)\n"
                    "(input nothing for default: {}): ".format(steps, config.read_only))

        if tls:
            if tls in ("y", "Y", "Yes", "yes"):
                tls = True
            else:
                tls = False

        else:
            tls = config.read_only

    config.tls_enabled = tls

    # 导出配置文件至
    config_path = None
    default_config = pathlib.Path.home().joinpath("i2ftp").joinpath("server_conf.json").as_posix()

    while config_path is None:
        config_path = input("step 8/{}: Saving config file to...\n"
                            "(input nothing for default: {}): ".format(steps, default_config))

        if not config_path:
            config_path = default_config

        try:
            path_fixer(config_path)
            config.dump(config_path)
        except Exception as err:
            print("error: {}".format(err))
            config_path = None

    # 生成启动脚本
    if os.name != "nt":
        choice = None

        while choice is None:
            choice = input("step 9/{}: Add to systemd for autostart? (Y/N)\n"
                           "(input nothing for default: True): ".format(steps))

            if choice:
                if choice in ("y", "Y", "Yes", "yes"):
                    choice = True
                else:
                    choice = False

            else:
                choice = True

        if choice:
            try:
                addon = 1
                path = "/etc/systemd/system/i2ftps.service"
                while os.path.exists(path):
                    addon += 1
                    path = "/etc/systemd/system/i2ftps{}.service".format(addon)
                text = generate_systemd(config_path, addon)
                with open("/tmp/i2ftp-setup_1.cache", "w") as f:
                    f.write(text)
                    f.close()
                if addon == 1:
                    addon = ""
                with open("/tmp/i2ftp-setup_2.cache", "w") as f:
                    f.write("#!/bin/sh\n"
                            "mv /tmp/i2ftp-setup_1.cache {}\n"
                            "systemctl enable i2ftps{}.service".format(path, addon))
                    f.close()
                print(" ==> root permission required, please make sure you are one of Sudoers")
                os.system("sudo bash /tmp/i2ftp-setup_2.cache")

            except Exception as err:
                print("error: {}".format(err))

            os.system("rm /tmp/i2ftp-setup_*.cache")


if __name__ == '__main__':
    main()
