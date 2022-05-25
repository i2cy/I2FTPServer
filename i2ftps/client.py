#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author: i2cy(i2cy@outlook.com)
# Project: I2FTPServer
# Filename: client
# Created on: 2022/5/24

import os
import time
import json
import tqdm
import hashlib
import pathlib
from i2cylib.network import Client
from i2cylib.utils import Logger
from i2ftps.server import VERSION


class I2ftpClient:

    def __init__(self, hostname, key=b"&90%]>__AdfI2FTP$F%_+@$^:aBasicKey%_+@-$^:>",
                 port=26842, logger=None, max_buffer_size=1000, timeout=15):
        self.version = b"I2FTP " + VERSION.encode("utf-8")
        if logger is None:
            logger = Logger()
        self.logger = logger
        self.timeout = timeout
        self.i2clt = Client(hostname, port, key, logger=logger, max_buffer_size=max_buffer_size)

        self.__header = "[I2FTP]"
        self.flag_download_busy = False

    def __del__(self):
        self.i2clt.reset()

    def send_command(self, cmd, feedback=True):
        self.i2clt.send(cmd)

        if feedback:
            status, ret = self.get_feedback()

            return status, ret

    def get_feedback(self):
        feed = self.i2clt.get(timeout=self.timeout)

        status = False
        ret = "timeout when receiving feedback"

        if feed is not None:
            status, ret = feed.split(b",", 1)
            status = bool(status[0])

        if not status:
            ret = ret.decode("utf-8")

        return status, ret

    def connect(self, timeout=None):
        if timeout is None:
            timeout = self.timeout
        else:
            self.timeout = timeout
        err = ""
        self.i2clt.connect(timeout=timeout)
        version = self.i2clt.get(timeout=timeout)
        if version != self.version:
            err = "failed to match server version, server: {} client: {}".format(
                version, self.version
            )
            self.logger.ERROR("{} ".format(self.__header, err))
            self.i2clt.reset()
        return self.i2clt.connected, err

    def disconnect(self):
        return self.i2clt.reset()

    def list(self, path):
        cmd = "LIST,{}".format(path).encode("utf-8")

        status, ret = self.send_command(cmd)

        if status:
            ret = ret.decode("utf-8")
            ret = json.loads(ret)

        return status, ret

    def download(self, path):
        cmd = "GETF,{}".format(path).encode("utf-8")

        # 获得会话ID
        status, ret = self.send_command(cmd)

        if status:
            session_id = ret
            # 获得文件信息
            status, file_details = self.list(path)
            if not status:
                return status, file_details
            assert isinstance(file_details, dict)
            file_details = file_details[pathlib.Path(path).name]
            # 新建下载会话（新连接）
            ret = DownloadSession(session_id, file_details,
                                  self.i2clt.address[0], key=self.i2clt.key, port=self.i2clt.address[1],
                                  logger=self.logger, max_buffer_size=self.i2clt.max_buffer,
                                  timeout=self.timeout)
            status, res = ret.connect()
            if not status:
                return status, res

        return status, ret


class DownloadSession(I2ftpClient):

    def __init__(self, session_id, file_details, hostname,
                 key=b"&90%]>__AdfI2FTP$F%_+@$^:aBasicKey%_+@-$^:>",
                 port=26842, logger=None, max_buffer_size=1000, timeout=15):
        
        super(DownloadSession, self).__init__(hostname, key, port, logger, max_buffer_size, timeout)
        self.session_id = session_id
        self.details = file_details
        self.closed = False
        self.hash_object = hashlib.md5()
        self.length = file_details["size"]

    def __del__(self):
        if not self.closed:
            cmd = b"CLOZ," + self.session_id
            self.send_command(cmd, feedback=False)
        super(DownloadSession, self).__del__()

    def __len__(self):
        return self.length

    def __getitem__(self, item):
        if self.flag_download_busy:
            raise Exception("client download busy, only one downloading quest a time")
        if self.closed:
            raise Exception("session closed")

        if isinstance(item, slice):
            cmd = b"DOWN," + self.session_id + b","

            start = item.start
            if start < 0:
                start = self.length - start
            stop = item.stop
            if stop < 0:
                stop = self.length - stop

            cmd += int(start).to_bytes(8, "little", signed=False) + b","
            cmd += int(stop).to_bytes(8, "little", signed=False)
            length = stop - start
            dat = b""
            self.flag_download_busy = True
            self.send_command(cmd, feedback=False)

            while len(dat) < length:
                status, fed = self.get_feedback()
                if not status:
                    raise Exception(fed)
                if start + len(dat) != int().from_bytes(dat[:8], "little", signed=False):
                    raise Exception("expecting package loss, received index {} (expecting {})".format(
                        int().from_bytes(dat[:8], "little", signed=False), start + len(dat)
                    ))
                dat += fed[9:]
            ret = dat[::item.step]

        else:
            cmd = b"DOWN," + self.session_id + b","
            if item < 0:
                item = self.length - item
            cmd += int(item).to_bytes(8, "little", signed=False) + b","
            cmd += int(item + 1).to_bytes(8, "little", signed=False)
            status, ret = self.send_command(cmd)
            if not status:
                self.flag_download_busy = False
                raise Exception(ret)
            if item != int().from_bytes(ret[:8], "little", signed=False):
                self.flag_download_busy = False
                raise Exception("expecting package loss, received index {} (expecting {})".format(
                    int().from_bytes(ret[:8], "little", signed=False), item
                ))
            ret = ret[9:]

        self.flag_download_busy = False
        return ret

    def close(self):
        if self.closed:
            return self.closed, -1
        cmd = b"CLOZ," + self.session_id
        status, ret = self.send_command(cmd)
        if status:
            self.closed = True
            ret = ret.decode("utf-8")
            ret = self.hash_object.hexdigest() == ret

        super(DownloadSession, self).disconnect()

        return status, ret

    def to_file(self, filename, verbose=True, close_session_when_done=True):
        if self.flag_download_busy:
            raise Exception("client download busy, only one downloading quest a time")
        if self.closed:
            raise Exception("session closed")
        self.hash_object = hashlib.sha256()
        f = open(filename, "wb")

        received = 0

        cmd = b"DOWN," + self.session_id + b","
        cmd += b"\x00" * 8 + b","
        cmd += int(self.length).to_bytes(8, "little", signed=False)
        self.flag_download_busy = True
        self.send_command(cmd, feedback=False)

        status, hash_res = False, -1
        if verbose:
            pbar = tqdm.tqdm(desc=pathlib.Path(filename).name, total=self.length,
                             unit="B", unit_scale=True)

        while received < self.length:
            status, fed = self.get_feedback()
            if not status:
                raise Exception(fed)
            if received != int().from_bytes(fed[:8], "little", signed=False):
                if verbose:
                    pbar.close()
                raise Exception("expecting package loss, received index {} (expecting {})".format(
                    int().from_bytes(fed[:8], "little", signed=False), received
                ))
            dat = fed[9:]
            self.hash_object.update(dat)
            received += f.write(dat)
            if verbose:
                pbar.update(len(dat))

        if verbose:
            pbar.close()

        if close_session_when_done:
            status, hash_res = self.close()
        else:
            status = True

        return status, hash_res


if __name__ == '__main__':
    test_server = "i2cy.tech"
    test_port = 26842
    test_key = b"&90%]>__AdfI2FTP$F%_+@$^:aBasicKey%_+@-$^:>"
    test_file = "small.mp4"
    test_log = "test.log"

    clt = I2ftpClient(test_server, test_key, test_port, logger=Logger(test_log, echo=False))

    clt.connect()
    print("test server connected")

    print("<-> listing root files")
    state, data = clt.list(".")
    print("<*> LIST test result: {}".format(state))
    print("    files under root: \n{}".format(json.dumps(data, indent=2)))

    print("<-> downloading test file {}".format(test_file))
    state, session = clt.download(test_file)
    print("<*> GETF test result: {}".format(state))
    if isinstance(session, DownloadSession):
        state, md5_res = session.to_file(test_file, True)
    else:
        state, md5_res = False, False
    print("<*> DOWN test result: {}".format(state))
    print("<*> file hash matching result: {}".format(md5_res))

    clt.disconnect()
    print("disconnected from server")
    print("test ended")