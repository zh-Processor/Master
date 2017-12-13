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
import json

#datebase:数据库名
#port：gamebox给主控开放的端口
#timeout：超时时间
#Retrys：重试次数
#team0:{name , pwn1 , pwn2 , web1 , web2 , sql_username , sql_password , pwn1_down , pwn2_down , web1_down , web2_down}
#line 53 , line 75 需添加地址


max_rank = 2000
mul = 1.2
per_rank = 500
datebase = ''
port = 80
timeout = 3
Retrys = 2
max_round = 100
team0 = ['vidar' , '127.0.0.1' , '127.0.0.1' ,'127.0.0.1' ,'127.0.0.1' ,'username' , 'password' , 0 , 0 , 0 , 0]

token = 'mDktXt32gPdO9C*4G%JO*nMi^9C7$mzR'
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

def rank(teamname):
    inc = per_rank
    for i in range(down_round):
        inc = inc * mul
    if inc >= max_rank:
        inc = max_rank
    for j in range(Retrys):
        try:
            s = requests.Session()
            data = {"teamName": teamname, "inc": inc}
            r = s.post("http://xxxx/Team/incScore",data = data)
            if r.status_code == 200:
                content = r.content
                logger.info("[Rank] Post rank sucess")
            else:
                logger.error("[Rank] Post rank failure")
        except requests.exceptions.ConnectTimeout:
            logger.warn("[Rank] Time out ")
            continue
        except:
            logger.warn("[Rank] Unexpected Error")
            traceback.print_exc()
            continue

def getround():
    for i in range(Retrys):
        try:
            s = requests.Session()
            r = s.get("http://xxxx/System/info")
            if r.status_code == 200:
                content = r.content
                logger.info("[ROUND] Get round sucess")
            else:
                logger.error("[ROUND] Get round failure")
        except requests.exceptions.ConnectTimeout:
            logger.warn("[ROUND] Time out ")
            continue
        except:
            logger.warn("[ROUND] Unexpected Error")
            traceback.print_exc()
            continue
    result = json.load(content)
    return result[round]


def buff(team_name,challenge_name):
    for i in range(Retrys):
        try:
            s = requests.Session()
            data = {"teamName": team_name, "challengeName": challenge_name, "status": status, "token": token}
            r = s.post("http://xxxx/System/setServerStatus", data=data)
            if r.status_code == 200:
                content = r.content
                logger.info("[POST] Post buff sucess")
            else:
                logger.error("[POST] Post buff failure")
        except requests.exceptions.ConnectTimeout:
            logger.warn("[POST] Time out ")
            continue
        except:
            logger.warn("[POST] Unexpected Error")
            traceback.print_exc()
            continue

def connectip(ip):
    global database

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
            logger.warn("[FLASH] [{}] Unexpected Error".format(ip))
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
    for index in range(len(team)):
        if ip in team[index]:
            team_name = team[index][0]
            now_team = team[index]

    for i in xrange(Retrys):
        try:
            if ip in web1list:
                ok = webcheck1(ip)
                name_1 = 'web1'
                index_1 = 9
            elif ip in web2list:
                ok = webcheck2(ip)
                name_1 = 'web2'
                index_1 = 10
            elif ip in pwn1list:
                ok = pwncheck1(ip)
                name_1 = 'pwn1'
                index_1 = 7
            elif ip in pwn2list:
                ok = pwncheck2(ip)
                name_1 = 'pwn2'
                index_1 = 8
            
            if ok == False:
                logger.warn("[CHECK] [{}] Check {} Failure" .format(ip , name_1))
                status = 'down'
                buff(now_team , name[index] , status) 
                team[index][index_1] += 1
                rank(team[index][0])
            else:
                logger.debug("[CHECK] [{}] Check {} Success".format(ip , name_1))
                status = 'up'
                buff(now_team , name[index] , status)
                team[index][index_1] = 0
        except:
            logger.warning("[CHECK] [{}] [{}] Error....".format(ip , name_1))
            traceback.print_exc()
            break
        except requests.exceptions.ConnectTimeout:
            logger.warn("[CHECK] [{}] [{}] Time out".format(ip , name_1))
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
