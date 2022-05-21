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

clt = Client("localhost", 2684, b"&90%]>__AdfI2FTP$F%_+@$^:aBasicKey%_+@-$^:>",
             logger=Logger(level="INFO"))
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

#while True:
#    splits.append(fp)
#    if total_size - fp < 240000:
#        break
#    else:
#        fp += 240000
#
#for ele in splits:
#    clt.send(b"DOWN," + session + b"," + int(ele).to_bytes(8, "little"))

pbar = tqdm.tqdm(total=total_size, unit_scale=True, unit="B")

sha256 = hashlib.sha256()

f = open("D:/" + TEST_FILENAME, "wb+")
f.close()

batch_requested = False
exceeded = False

while True:
    feed = clt.get(timeout=0.5)
    if feed is None:
        if fp < total_size and not batch_requested:
            batch_requested = True
            for i in range(20):
                clt.send(b"DOWN," + session + b"," + int(fp).to_bytes(8, "little", signed=False))
                fp += 240000
                if fp >= total_size:
                    break
        time.sleep(0.001)
        continue

    batch_requested = False
    ret, data = feed.split(b",", 1)

    f = open("D:/" + TEST_FILENAME, "ab")
    fd += f.write(data)
    f.close()

    pbar.update(len(data))

    if fp < total_size:
        #print(fd)
        clt.send(b"DOWN," + session + b"," + int(fp).to_bytes(8, "little", signed=False))
        fp += 240000
    else:
        if not exceeded:
            print("exceeded")
            exceeded = True

    if len(data) < 240000:
        len(data)
        break

pbar.close()

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
