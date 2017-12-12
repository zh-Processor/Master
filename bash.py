from pwn import *
import requests
import time
import logging
import threading
import random
from log import logger
from log import log

iplist = ['127.0.0.1']
port = 80
Retrys = 10
timeout = 3

def bash(ip):
    for j in xrange(Retrys):
        try:
            p = remote(ip , port)
        except requests.exceptions.ConnectTimeout:
            logger.warn("Bash opt Time out when login !!!")
            continue
        except:
            logger.warn("Unexpected Error when Bash opt")
            continue
    opt = raw_input("Your opt:")

    for i in xrange(Retrys):
        try:
            p.sendline(opt)
        except requests.exceptions.ConnectTimeout:
            logger.warn("Bash opt Time out when sendline!!!")
            continue
        except:
            logger.warn("Unexpected Error when Bash opt")
            continue

def opt():
    threads_bash = []
    for ip in iplist:
		try:
			w = threading.Thread(target=bash, name='thread for %s' % ip, args=(ip,))
			w.start()
			threads_bash.append(w)
		except:
			logger.error("Thread error...")

def main():
    while 1:
        opt()

if __name__ == '__main__':
    main()