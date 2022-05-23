#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author: i2cy(i2cy@outlook.com)
# Project: I2FTPServer
# Filename: test
# Created on: 2022/5/19

import os
import time

from i2cylib import Client, Logger
import hashlib
import json
import tqdm

TEST_FILENAME = "tc.mp4"

clt = Client("i2cy.tech", 26842, b"&90%]>__AdfI2FTP$F%_+@$^:aBasicKey%_+@-$^:>",
             logger=Logger('test.log', level="INFO", echo=False), max_buffer_size=1000)
clt.connect()

print("Version:", clt.get(timeout=5))

clt.send(b"LIST,.")

lists = clt.get(timeout=5).split(b",", 1)[1].decode()
lists = json.loads(lists)

total_size = lists[TEST_FILENAME]["size"]

clt.send(b"GETF," + TEST_FILENAME.encode())
session = clt.get(timeout=5)
session = session.split(b",", 1)[1]
fd = 0
file = b""

splits = []
fp = 0

pbar = tqdm.tqdm(total=total_size, unit_scale=True, unit="B")

sha256 = hashlib.sha256()

f = open("D:/" + TEST_FILENAME, "wb+")
f.close()

clt.send(b"DOWN," + session + b"," + int(fp).to_bytes(8, "little", signed=False) + b"," +
         int(fp).to_bytes(8, "little", signed=False))

missed = []

while True:
    feed = clt.get(timeout=5)
    if feed is None:
        break

    ret, data = feed.split(b",", 1)
    fp_ret = int.from_bytes(data[:8], "little", signed=False)
    #print("fp_ret got:", fp_ret, "fp now:", fp)
    data = data[9:]

    f = open("D:/" + TEST_FILENAME, "ab")
    if fp_ret != fp:  # 当传输的包偏移量不符合顺序时（可能发生了丢包）
        #print(feed[0:14])
        #print("inorder package, fp_ret: {} fp: {}".format(fp_ret, fp))
        if fp_ret > fp:
            f.write(bytes(fp_ret - fp))
            missed.append((fp, fp_ret))
        else:
            f.seek(fp_ret)

    fd += f.write(data)
    fp += len(data)
    f.close()

    pbar.update(len(data))

    if fd == total_size:
        break

for fp_s, fp_end in missed:
    clt.send(b"DOWN," + session + b"," + int(fp_s).to_bytes(8, "little", signed=False) + b"," +
             int(fp_end).to_bytes(8, "little", signed=False))
    total_size = fp_end - fp_s
    fp = fp_s
    while True:
        feed = clt.get(timeout=5)
        if feed is None:
            break

        ret, data = feed.split(b",", 1)
        fp_ret = int.from_bytes(data[:8], "little", signed=False)

        f = open("D:/" + TEST_FILENAME, "ab")
        f.seek(fp)
        if fp_ret != fp:  # 当传输的包偏移量不符合顺序时（可能丢包）
            if fp_ret > fp:
                f.write(bytes(fp_ret - fp))
                missed.append((fp, fp_ret))
                print("missed", (fp, fp_ret))
            else:
                f.seek(fp_ret)

        fd += f.write(data)
        fp += len(data)
        f.close()

        pbar.update(len(data))

        if fd == total_size:
            break

pbar.close()

print("Verifying file's sha256 sum")
f = open("D:/" + TEST_FILENAME, "rb")
while True:
    data = f.read(8192)
    if not data:
        break
    sha256.update(data)
ret = False

while not ret:
    clt.send(b"CLOZ,"+session)
    ret, hashs = clt.get(timeout=5).split(b",", 1)
    ret = int().from_bytes(ret, "little")
    time.sleep(0.5)

print("received size:", fd)
print("total size:   ", total_size)
print(hashs.decode(), sha256.hexdigest())
print("sha256 sum check: {}".format(sha256.hexdigest() == hashs.decode()))

clt.reset()
