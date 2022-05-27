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
from i2ftps.server import VERSION, SIGNAL_PACKAGE_SIZE


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
        ret = b"timeout when receiving feedback"

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

    def upload(self, path):
        cmd = "PULF,{}".format(path).encode("utf-8")

        # 获取会话ID
        status, ret = self.send_command(cmd)

        if status:
            session_id = ret
            # 新建上传会话（新连接）
            ret = UploadSession(session_id, path,
                                self.i2clt.address[0], key=self.i2clt.key, port=self.i2clt.address[1],
                                logger=self.logger, max_buffer_size=self.i2clt.max_buffer,
                                timeout=self.timeout)
            status, res = ret.connect()
            if not status:
                return status, res

        return status, ret


class UploadSession(I2ftpClient):

    def __init__(self, session_id, filename, hostname,
                 key=b"&90%]>__AdfI2FTP$F%_+@$^:aBasicKey%_+@-$^:>",
                 port=26842, logger=None, max_buffer_size=1000, timeout=15):
        super(UploadSession, self).__init__(hostname, key, port, logger, max_buffer_size, timeout)
        self.session_id = session_id
        self.closed = False
        self.filename = filename
        self.fp = 0
        self.length = 0
        self.hash_object = hashlib.md5()

    def __del__(self):
        if not self.closed:
            cmd = b"CLOZ," + self.session_id
            self.send_command(cmd, feedback=False)
        super(UploadSession, self).__del__()

    def __len__(self):
        return self.length

    def close(self):
        if self.closed:
            return self.closed, -1
        cmd = b"CLOZ," + self.session_id
        status, ret = self.send_command(cmd)
        if status:
            self.closed = True

        super(UploadSession, self).disconnect()

        return status, ret

    def upload(self, filename, pre_upload_size=5, verbose=True, close_session_when_finished=True):
        f = open(filename, "rb")

        cnt = 0

        if verbose:
            pbar = tqdm.tqdm(desc=pathlib.Path(filename).name, total=os.path.getsize(filename),
                             unit="B", unit_scale=True)

        while True:
            dat = f.read(SIGNAL_PACKAGE_SIZE)
            if not dat:
                break

            pbar.update(len(dat))

            cmd = b"UPLD," + self.session_id + b"," + self.fp.to_bytes(8, "little", signed=False)
            cmd += b"," + dat

            self.hash_object.update(dat)

            self.send_command(cmd, feedback=False)

            if cnt > pre_upload_size:
                status, ret = self.get_feedback()
                if not status:
                    raise Exception(ret)
                fed_fp = int().from_bytes(ret, "little", signed=False)
                if fed_fp != self.fp - pre_upload_size * SIGNAL_PACKAGE_SIZE:
                    raise Exception("expecting package loss, received index {} (expecting {})".format(
                        int().from_bytes(ret, "little", signed=False),
                        self.fp - pre_upload_size * SIGNAL_PACKAGE_SIZE))
                last_fp = fed_fp
                self.length = last_fp

            self.fp += len(dat)
            cnt += 1

        if verbose:
            pbar.close()

        for i in range(pre_upload_size + 1):
            status, ret = self.get_feedback()
            if not status:
                raise Exception(ret)
            fed_fp = int().from_bytes(ret, "little", signed=False)

            if i < pre_upload_size:
                if fed_fp != last_fp + SIGNAL_PACKAGE_SIZE:
                    raise Exception("expecting package loss, received index {} (expecting {})".format(
                        int().from_bytes(ret, "little", signed=False),
                        last_fp + SIGNAL_PACKAGE_SIZE))
                last_fp = fed_fp

            else:
                if fed_fp != self.fp:
                    raise Exception("expecting package loss, received index {} (expecting {})".format(
                        int().from_bytes(ret, "little", signed=False),
                        self.fp))
                last_fp = fed_fp

            self.length = last_fp

        if close_session_when_finished:
            self.close()

    def verify(self, timeout=20):
        cmd = "GETF,{}".format(self.filename).encode("utf-8")

        # 获得会话ID
        status, ret = self.send_command(cmd)

        if not status:
            return False

        session_id = ret

        status = False

        cmd = b"CLOZ," + session_id

        t0 = time.time()
        while not status:
            status, ret = self.send_command(cmd)
            if not status:
                time.sleep(1)
            if time.time() - t0 > timeout:
                ret = b"failed"
                break

        ret = ret.decode("utf-8")
        ret = self.hash_object.hexdigest() == ret

        return ret


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

    def to_file(self, filename, verbose=True, close_session_when_finished=True):
        if self.flag_download_busy:
            raise Exception("client download busy, only one downloading quest a time")
        if self.closed:
            raise Exception("session closed")
        self.hash_object = hashlib.md5()
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

        if close_session_when_finished:
            status, hash_res = self.close()
        else:
            status = True

        return status, hash_res


if __name__ == '__main__':
    test_server = "i2cy.tech"
    test_port = 26842
    test_key = b"&90%]>__AdfI2FTP$F%_+@$^:aBasicKey%_+@-$^:>"
    test_file = "small.mp4"
    test_upload_name = "test_dir/little.mp4"
    test_log = "test.log"

    clt = I2ftpClient(test_server, test_key, test_port, logger=Logger(test_log, echo=False))

    clt.connect()
    print("  > test server connected")

    print("  > listing root files")
    state, data = clt.list(".")
    print("<*> LIST test result: {}".format(state))
    json_data = data
    assert isinstance(json_data, dict)
    print("    files under root: \n    {}".format([ele for ele in json_data if not json_data[ele]["is_dir"]]))
    print("    dirs under root: \n    {}".format([ele for ele in json_data if json_data[ele]["is_dir"]]))

    print("  > downloading test file {}".format(test_file))
    state, session = clt.download(test_file)
    if isinstance(session, DownloadSession):
        try:
            state, md5_res = session.to_file(test_file, True)
        except Exception as err:
            state = err
            md5_res = False
    else:
        state, md5_res = False, False
    print("<*> GETF test result: {}".format(state))
    print("<*> DOWN test result: {}".format(state))
    print("<*> file hash matching result: {}".format(md5_res))
    print("    file md5 sum: {}".format(session.hash_object.hexdigest()))

    print("  > uploading test file {} as {} on server".format(test_file, test_upload_name))
    state, session = clt.upload(test_upload_name)
    if isinstance(session, UploadSession):
        try:
            session.upload(test_file, close_session_when_finished=False)
        except Exception as err:
            state = err
    else:
        state = False
    print("<*> PULF test result: {}".format(state))
    print("<*> UPLD test result: {}".format(state))
    print("  > verifying data hash value on server")
    t0 = time.time()
    state = session.verify()
    ts = time.time() - t0
    print("<*> file hash matching result: {}".format(state))
    print("    verification time: {:.4f}s".format(ts))
    print("    file md5 sum: {}".format(session.hash_object.hexdigest()))
    session.close()

    clt.disconnect()
    print("  > disconnected from server")
    print("  > test ended")
