from pwn import *
import requests
import time
import logging
import threading
import random
import traceback
from log import logger
from log import log

iplist = ['127.0.0.1']
port = 80
Retrys = 10
timeout = 3

def bash(ip):
    for j in xrange(Retrys):
        try:
            ipip = "'" + ip + "'"
            p = remote(ipip , port)
        except requests.exceptions.ConnectTimeout:
            logger.warn("[BASH] [{}] Time out".format(ip))
            continue
        except:
            logger.warn("[BASH] [{}] Unexpected Error when Bash opt".format(ip))
            traceback.print_exc()
            continue

    for i in xrange(Retrys):
        try:
            p.sendline(opt)
        except requests.exceptions.ConnectTimeout:
            logger.warn("[BASH] [{}] Time out ".format(ip))
            continue
        except:
            logger.warn("[BASH] [{}] Unexpected Error".format(ip))
            traceback.print_exc()
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
            traceback.print_exc()

def main():
    while 1:
        opt = raw_input("Your opt:")
        opt()

if __name__ == '__main__':
    main()