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
import traceback

port = 80
timeout = 3
Retrys = 2
max_round = 100
team0 = ['vidar' , '127.0.0.1' , '127.0.0.1' ,'127.0.0.1' ,'127.0.0.1' ,'username' , 'password']

name = ['web1' , 'web2' , 'pwn1' , 'pwn2']
team = [team0 ,team1 ,team2 ,team3 ,team4 ,team5 ,team6 ,team7 ,team8 ,team9]
pwn1list = []
pwn2list = []
web1list = []
web2list = []
iplist = pwn1list + pwn2list + web1list + web2list
for index in range(len(team)):
    pwn1list.append(team[index][1])
    pwn2list.append(team[index][2])
    web1list.append(team[index][3])
    web2list.append(team[index][4])

def sha256(str):
    m = hashlib.sha256()   
    m.update(str)
    return m.hexdigest()

def connectip(ip):
    if ip in pwn1list:
        challenge_name = "pwn1"
        challenge_port = pwn1_port
    elif ip in pwn2list:
        challenge_name = "pwn2"
        challenge_port = pwn2_port
    elif ip in web1list:
        challenge_name = "web1"
        challenge_port = web1_port
    else:
        challenge_name = "web2"
        challenge_port = web2_port

    for index in range(len(team)):
        if ip in team[index]:
            team_name = team[index][0]
            now_team = team[index]

    flag = "hctf{" + sha256(round + challenge_name + team_name + "f33601c10397b25e789c85bce5f2fbfd") + "}"

    logger.info("Start connect %s" % ip)
    ipip = "'" + ip + "'"
    for j in xrange(Retrys):
        try:
            p = remote(ipip , port)
        except requests.exceptions.ConnectTimeout:
            logger.warn("[FLUSH] [{}] Time out ".format(ip))
            continue
        except:
            logger.warn("[FLASH] [{}] Unexpected Error when connect".format(ip))
            traceback.print_exc()
            continue

        logger.info("Start flush %s" % ip)
        if ip in pwn1list or ip in pwn2list:
            payload = 'echo ' + '"' + flag + '" ' + '> ' + 'flag.txt'
            try:
                p.sendline(payload)
                break
            except requests.exceptions.ConnectTimeout:
                logger.warn("[FLUSH] [{}] [{}] Time out".format(ip , challenge_name))
                continue
            except IOError:
                logger.warn("[FLUSH] [{}] [{}] IOError!".format(ip , challenge_name))
                continue
            except:
                logger.warn("[FLUSH] [{}] [{}] Unexpected Error".format(ip , challenge_name))
                traceback.print_exc()
                continue
        else:
            query = "update {database} set flag={flag} where xxxxxx".format(database=datebase, flag=flag)
            payload = "mysql -u {username} -p {password} -e \'{query}\'".format(username=now_team[5], password=now_team[6], query=query)
            try:
                p.sendline(payload)
                break
            except requests.exceptions.ConnectTimeout:
                logger.warn("[FLUSH] [{}] [{}] Time out".format(ip , challenge_name))
                continue
            except IOError:
                logger.warn("[FLUSH] [{}] [{}] IOError!".format(ip , challenge_name))
                continue
            except:
                logger.warn("[FLUSH] [{}] [{}] Unexpected Error".format(ip , challenge_name))
                traceback.print_exc()
                continue

def check(ip):
    logger.info("Start check %s" %ip)
    for i in xrange(Retrys):
        try:
            for index in range(len(name)):
                try:
                    if name[index] in web1list:
                        ok = webcheck1(ip)
                    elif name[index] in web2list:
                        ok = webcheck2(ip)
                    elif name[index] in pwn1list:
                        ok = pwncheck1(ip)
                    elif name[index] in pwn2list:
                        ok = pwncheck2(ip)

                    if ok == False:
                        logger.warn("[CHECK] [{}] Check {} Failure" .format(ip , name[index]))
                    else:
                        logger.debug("[CHECK] [{}] Check {} Success".format(ip , name[index]))
                except:
                    logger.warning("[CHECK] [{}] [{}] Error....".format(ip , name[index]))
                    traceback.print_exc()
            break
        except requests.exceptions.ConnectTimeout:
            logger.warn("[CHECK] [{}] [{}] Time out".format(ip , name[index]))
            continue
        except:
            logger.warn("Unexpected Error")
            traceback.print_exc()
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
                    traceback.print_exc()

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
                    traceback.print_exc()

            for t in threads_check:
    			t.join()

            logger.info("Round %s is finished" % round)
            if round >= max_round:
    			logger.warn("All round finished...")
    			break

if __name__ == '__main__':
    main()