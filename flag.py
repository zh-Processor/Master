from pwn import *
import hashlib
import time
import random

def sha256(str):
    m = hashlib.sha256()   
    m.update(str)
    return m.hexdigest()

def connet(ip, port):
    ip = "'" + ip + "'"
    p = remote(ip, port)
    pwd = "Sakura"
    \rtn = ' '             #gamebox固定返回
    p.sendline(pwd)
    recv = p.recv()
    if recv == rtn：
        print 'Connect Success'
    return True

def flush():
    teamid = getteamid()
    flag = 'flag{' + sha256(teamid + now_round * 5 + 'Vidar_Team' * 5) + '}'
    payload = 'echo ' + '"' + flag + '" ' + '> ' + 'flag.txt'
    p.sendline(payload)

def round_check():
    while True:
        now_round = getround()   #从平台获取round
        if now_round == old_round:
            time.sleep(1)
        else:
            old_round = now_round
            return False

def is_OK(ip , port):
    if connet(ip , port) == True:
        while True:
            if round_check() == False:
                flush()
                check()
    else:
        connet(ip , port)
        print 'again'
        is_OK(ip,port)

def check(ip):   #多线程
    delay = random.randint(10,180)
    time.sleep(delay)
    name = ['web1' , 'web2' , 'pwn1' , 'pwn2']
    for index in range len(name):
        if name[index] == 'web1':
            ok = webcheck1(ip)
        if name[index] == 'web2':
            ok = webcheck2(ip)
        if name[index] == 'pwn1':
            ok = pwncheck1(ip)
        if name[index] == 'pwn2':
            ok = pwncheck2(ip)
        if ok == False:
            print "down:",name,":",ip 

def scp(yourfile,ip,port):
    connet(ip,port)
    road = 'root@' + ip + '/tmp'
    payload = 'scp ' + yourfile + ' ' + road
    p.sendline(payload)

def bash(opt,ip,port):
    connet(ip,port)
    payload = opt
    p.sendline()