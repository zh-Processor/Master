#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import time
import logging
import threading
import random
from log import logger
from log import log
from pwn import *

iplist = ['127.0.0.1']
name = ['web1' , 'web2' , 'pwn1' , 'pwn2']
port = 80
timeout = 3
Retrys = 2
max_round = 100

def sha256(str):
    m = hashlib.sha256()   
    m.update(str)
    return m.hexdigest()

def connectip(ip):
    ip = "'" + ip + "'"
    flag = "hctf{" + sha256(round + "f33601c10397b25e789c85bce5f2fbfd") + "}"
    payload = 'echo ' + '"' + flag + '" ' + '> ' + 'flag.txt'

    logger.info("Start connect %s" % ip)

    for j in xrange(Retrys):
        try:
            p = remote(ip , port)
        except requests.exceptions.ConnectTimeout:
            logger.warn("Time out when connect!!!")
            continue
        except:
            logger.warn("Unexpected Error when connect")
            continue

        logger.info("Start flush %s" % ip)

        try:
            p.sendline(payload)
            break
        except requests.exceptions.ConnectTimeout:
            logger.warn("Time out when flush flag!!!")
            continue
        except IOError:
            logger.warn("IOError!")
            continue
        except:
            logger.warn("Unexpected Error when flush flag")
            continue

def check(ip):
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
            break
        except requests.exceptions.ConnectTimeout:
            logger.warn("Time out !!!")
            continue
        except:
            logger.warn("Unexpected Error")
            continue

def main():
    while 1:
        round = getround()
        old_round = round
        if round != old_round:
            logger.info("Start %d round" % round)
            logger.info("This round time is %s" % time.strftime('%H:%M:%S',time.localtime(time.time())))
            threads_connect = []
            for ip in iplist:
        		try:
        			w = threading.Thread(target=connectip, name='thread for %s' % ip, args=(ip,))
        			w.start()
        			threads_connect.append(w)
        		except:
        			logger.error("Thread error when connect...")

            for w in threads_connect:
                w.join()

            threads_check = []
            delay = random.randint(10,180)
            time.sleep(delay)
            for ip in iplist:
    			try:
    				t = threading.Thread(target=check, name='thread for %s' % ip, args=(ip,))
    				t.start()
    				threads_check.append(t)
    			except:
    				logger.error("Thread error when check...")

            for t in threads_check:
    			t.join()

            logger.info("Round %s is finished" % round)
            if round >= max_round:
    			logger.warn("All round finished...")
    			break

if __name__ == '__main__':
    main()