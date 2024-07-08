#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author: i2cy(i2cy@outlook.com)
# Project: I2FTPServer
# Filename: process_manage
# Created on: 2022/5/17

import os
import signal
import time
from i2cylib.network.I2TCP import Client
from i2cylib.utils.logger import Logger
from i2cylib.utils import args
from i2ftps.config import Config

LOGGER = Logger(level="INFO")
KILL_TIMEOUT = 20


def stop(config):
    # 连接到服务器
    assert isinstance(config, Config)
    LOGGER.INFO("[Main] stopping target server".format(config.port))
    LOGGER.INFO("[Main] connecting to target server at port {}".format(config.port))
    clt = Client("localhost", config.port, config.keychain, logger=LOGGER)

    try:
        clt.connect()
        flag = clt.get(timeout=5)
        if not "I2FTP" in flag.decode("utf-8"):
            raise Exception("target is not a I2FTP server")
    except Exception as err:
        LOGGER.ERROR("[Main] failed to connect to server, {}".format(err))
        return

    # 发送PCTL命令
    try:
        clt.send(b"PCTL,0")
        feedback = clt.get(timeout=5)
        ret, pid = feedback.split(b",", 1)
        pid = int().from_bytes(pid, "little", signed=False)
        LOGGER.INFO("[Main] got server process ID: {}".format(pid))
        clt.reset()
    except Exception as err:
        LOGGER.ERROR("[Main] server respond incorrectly, {}".format(err))
        return

    # 发送终止信号
    try:
        if os.name == 'nt':
            os.system("taskkill -f -t -pid {}".format(pid))
        else:
            os.kill(pid, signal.SIGINT)
            t0 = time.time()
            while True:
                time.sleep(0.5)
                if time.time() - t0 > KILL_TIMEOUT:
                    LOGGER.WARNING("[Main] process may not be killed, timeout")
                    break
                try:
                    os.kill(pid, signal.SIGUSR1)
                except ProcessLookupError:
                    LOGGER.INFO("[Main] process killed")
                    break
    except Exception as err:
        LOGGER.ERROR("[Main] failed to kill process, {}".format(
            err
        ))
