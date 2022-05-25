#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author: i2cy(i2cy@outlook.com)
# Filename: setup
# Created on: 2021/3/6

import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="i2ftps",  # Replace with your own username
    version="0.2.2",
    author="I2cy Cloud",
    author_email="i2cy@outlook.com",
    description="A FTP server based on I2TCP",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/i2cy/i2ftp-server",
    project_urls={
        "Bug Tracker": "https://github.com/i2cy/I2FTPServer/issues",
        "Source Code": "https://github.com/i2cy/I2FTPServer",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'i2cylib >= 1.8.14'
    ],
    packages=setuptools.find_packages(),
    python_requires=">=3.6",
    entry_points={'console_scripts':
        [
            "i2ftps-setup = i2ftps.config:main",
            "i2ftps = i2ftps.server:main"
        ]
    }
)
