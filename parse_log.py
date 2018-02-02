#!/usr/bin/env python2

import termios, sys

import datetime
import struct
import os

from util import p16, p32, u32, u64, hexdump, perm_to_str, c_str

dataoff = 0xbc*0x80#0x218*0x80#0xf*0x80#0x602*0x80#0xd500

f = open(sys.argv[1], 'rb').read()

cmdlog = f #[:dataoff]
#datalog = cmdlog #f[dataoff:]
datalogpos = 0
curpos = 0
i = 0

while curpos < len(f):
    cmdpos = curpos
    sessiontype = struct.unpack('<I', cmdlog[cmdpos:cmdpos+0x4])[0]
    print "cmd 0x%x(pos=0x%x) sessiontype %u:" % (i, cmdpos, sessiontype)
    cmd = cmdlog[cmdpos+0x4:cmdpos+0x4+0x7c]
    cmdhdr0 = struct.unpack('<I', cmd[0x0:0x4])[0]
    cmdhdr1 = struct.unpack('<I', cmd[0x4:0x8])[0]
    print hexdump(cmd)
    curpos+= 0x80

    #if cmd[0x10:0x10+0x4] == 'SFCO': # or (cmdhdr0 & 0xffff)==0x5
        #continue

    #if (cmdhdr0 & 0xffff)!=0x5:
    #    rawdata = cmd.find('SFCI')
    #    if rawdata != -1:
    #        rawdata = cmd[rawdata:]
    #        cmdid = struct.unpack('<I', rawdata[0x8:0x8+0x4])[0]
    #        if cmdid==0:
    #            cmdparams = struct.unpack('<III', rawdata[0x10:0x10+0xc])
    #            print "ID=0x%x, code=0x%x, flags=0x%x" % (cmdparams[0], cmdparams[1], cmdparams[2])

    if cmdhdr0==0x01110004 and cmdhdr1==0x00000c0b:
        rawdata = cmd.find('SFCI')
        if rawdata != -1:
            rawdata = cmd[rawdata:]
            cmdid = struct.unpack('<I', rawdata[0x8:0x8+0x4])[0]
            if cmdid==1:
                cmdparams = struct.unpack('<II', rawdata[0x10:0x10+0x8])
                print "fd=0x%x, request=0x%x" % (cmdparams[0], cmdparams[1])

    datalogpos = curpos
    bufsizes = cmdlog[datalogpos:datalogpos+0x20]
    if len(bufsizes) < 0x20:
        continue

    buffersizes = struct.unpack('<QQQQ', bufsizes)
    datalogpos+= 0x20

    for bufi in range(4):
        if buffersizes[bufi] == 0:
            continue
        print "buffer[%u]:" % (bufi)
        print hexdump(cmdlog[datalogpos:datalogpos+buffersizes[bufi]])
        datalogpos+= buffersizes[bufi]
    curpos = datalogpos
    i+=1

