#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author: i2cy(i2cy@outlook.com)
# Project: I2FTPServer
# Filename: test
# Created on: 2022/5/19

from i2cylib import Client
import hashlib
import json

clt = Client("localhost", 2684, b"&90%]>__AdfI2FTP$F%_+@$^:aBasicKey%_+@-$^:>")
clt.connect()

print("Version:", clt.get(timeout=5))

clt.send(b"LIST,.")

lists = clt.get(timeout=5).split(b",", 1)[1].decode()
lists = json.loads(lists)

total_size = lists["tc.mp4"]["size"]

clt.send(b"GETF,tc.mp4")
session = clt.get(timeout=5)
session = session.split(b",", 1)[1]
fd = 0
file = b""

splits = []
fp = 0
while True:
    splits.append(fp)
    if total_size - fp < 240000:
        break
    else:
        fp += 240000

for ele in splits:
    clt.send(b"DOWN," + session + b"," + int(ele).to_bytes(8, "little"))

sha256 = hashlib.sha256()

while True:
    ret, data = clt.get(timeout=5).split(b",", 1)

    sha256.update(data)
    fd += len(data)

    if len(data) < 240000 or not ret:
        break

clt.send(b"CLOZ,"+session)
ret, hashs = clt.get(timeout=5).split(b",", 1)

print("received size:", fd)
print("total size:   ", total_size)
print(hashs.decode(), sha256.hexdigest())
print("sha256 sum check: {}".format(sha256.hexdigest() == hashs.decode()))

with open("test.md", "wb") as f:
    f.write(file)
    f.close()
clt.reset()
