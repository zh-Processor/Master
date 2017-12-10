#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import time
import logging
import threading
import random
from core.log import logger
from core.log import log

iplist = ['127.0.0.1']
name = ['web1' , 'web2' , 'pwn1' , 'pwn2']
port = 80
round_time = 60
timeout = 3
Retrys = 2

bool ok

def run(ip):
    logger.info("Start check %s" %ip)
    for i in xrange(Retrys):
        try:
            for index in range(len(name)):
                if name[index] == 'web1':
                    ok = webcheck1(ip)
                elif name[index] == 'web2':
                    ok = webcheck2(ip)
                elif name[index] == 'pwn1':
                    ok = pwncheck1(ip)
                elif name[index] == 'pwn2':
                    ok = pwncheck2(ip)

                if ok == False:
                    logger.warn("Check for %s : %s Failure" % (ip , name[index]))
                else:
                    logger.debug("Check for %s : %s Success" % (ip , name[index]))
        except requests.exceptions.ConnectTimeout:
            logger.warn("Time out !!!")
            continue
        except:
            logger.warn("Unexpected Error")
            continue

def main():
    