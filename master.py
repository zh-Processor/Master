from pwn import *
import hashlib
import time
import random
import thread

def sha256(str):
    m = hashlib.sha256()   
    m.update(str)
    return m.hexdigest()

def connet(ip, port):
    ip = "'" + ip + "'"
    p = remote(ip, port)
    pwd = "Sakura"
    \rtn = ' '             #gamebox固定返回
    try:
        p.sendline(pwd)
    except IOError :
        print "pwd IO Error"
    except:
        print "Unexpected error"
    recv = p.recv()
    if recv == rtn：
        print 'Connect Success'
    return True

def flush():
    teamid = getteamid()
    flag = 'flag{' + sha256(teamid + now_round * 5 + 'Vidar_Team' * 5) + '}'
    payload = 'echo ' + '"' + flag + '" ' + '> ' + 'flag.txt'
    try:
        p.sendline(pwd)
    except IOError :
        print "flag IO Error"
    except:
        print "Unexpected error"

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
    else:
        connet(ip , port)
        print 'again'
        is_OK(ip,port)

def bash(opt,ip,port):
    connet(ip,port)
    payload = opt
    p.sendline()

thread.start_new_thread(is_OK , ip , port)
while True:
    opt = raw_input("Your opt")
    thread.start_new_thread(bash , ip , port , opt)

ip = []

