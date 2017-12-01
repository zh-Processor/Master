import thread

f = open("log" , 'a+')

def check(ip):   
    try:
        delay = random.randint(10,180)
        time.sleep(delay)
        name = ['web1' , 'web2' , 'pwn1' , 'pwn2']
        for index in range(len(name)):
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
                f.writelines(name , ip , "down")
            f.writelines(name , ip , "OK")
            
    except IOError :
        print name ":IO Error"
        f.writelines(name , ip , IO Error)
    except:
        print "Unexpected error"
        f.writelines(name , ip , "unexcepted error")

def checker():
    try:
        for ip in range len(ip):
            thread.start_new_thread( check , ip[len])
    except:
        print "Error: unable to start thread"

def round_check():
    while True:
        now_round = getround()   #从平台获取round
        if now_round == old_round:
            time.sleep(1)
        else:
            old_round = now_round
            return False
