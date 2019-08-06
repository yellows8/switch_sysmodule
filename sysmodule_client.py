#!/usr/bin/env python2

import sys

import datetime
import struct
import os

# pyusb is required.
import usb.core
import usb.util

import socket

from util import p16, p32, u32, u64, hexdump, perm_to_str, c_str

from sysmodule_ipc import *

class TransportCmd:
    def __init__(self, cmdid):
        self.buffer_types = []
        self.buffer_sizes = []
        self.buffers = []
        self.recv_ret = 0

        self.rawdata = ''
        self.add_raw_32(cmdid)

    def add_raw_64(self, val):
        self.rawdata += struct.pack('<Q', val)
    def add_raw_32(self, val):
        self.rawdata += struct.pack('<I', val)

    def add_sendbuf(self, buf):
        size = len(buf)
        self.buffer_types.append(0) # From host
        self.buffer_sizes.append(size)
        self.buffers.append(buf)

    def add_recvbuf(self, size):
        self.buffer_types.append(1) # To host
        self.buffer_sizes.append(size)
        self.buffers.append('')

    def _send_cmd(self, c):
        if len(self.rawdata) >= 0x100:
            raise Exception("TransportCmd: Rawdata too large.")
        if len(self.buffer_types) >= 4:
            raise Exception("TransportCmd: Too many buffers.")

        msg = ''

        msg += nxsm_auth # auth
        msg += struct.pack('<I', 0x4d53584e) # magic 'NXSM'
        msg += struct.pack('<I', 1) # version
        msg += struct.pack('<I', len(self.rawdata)>>2) # raw_data_size

        types_data = ''
        sizes_data = ''

        for i in range(4):
            tmp_type = 0
            tmp_size = 0
            if i < len(self.buffer_types):
                tmp_type = self.buffer_types[i]
                tmp_size = self.buffer_sizes[i]
            types_data+= struct.pack('<B', tmp_type) # buffer_types
            sizes_data+= struct.pack('<I', tmp_size) # buffer_sizes

        msg += types_data + sizes_data

        tmp_rawdata = self.rawdata
        tmp_rawdata += '\x00' * (0x100-len(tmp_rawdata))
        msg += tmp_rawdata # rawdata

        c.write_device(msg)
        for i in range(4):
            if i < len(self.buffer_types):
                if self.buffer_types[i]==0: # From host
                    c.write_device(self.buffers[i])

    def _recv_cmd(self, c, noprint=False):
        msg = c.read_device(0x140)

        pos = 0x0
        cursize = 0x20
        msgauth = msg[pos:pos+cursize]
        pos+= cursize
        if msgauth != nxsm_auth:
            raise Exception("TransportCmd: Recv-msg auth is invalid.")

        cursize = 0x4
        magic = struct.unpack('<I', msg[pos:pos+cursize])[0]
        pos+= cursize
        if magic != 0x4d53584e:
            raise Exception("TransportCmd: Recv-msg magic is invalid: 0x%08x." % magic)
        cursize = 0x4
        version = struct.unpack('<I', msg[pos:pos+cursize])[0]
        pos+= cursize
        if version != 1:
            raise Exception("TransportCmd: Recv-msg version is invalid: 0x%08x." % version)
        cursize = 0x4
        raw_data_size = struct.unpack('<I', msg[pos:pos+cursize])[0]
        pos+= cursize
        if raw_data_size >= (0x100>>2):
            raise Exception("TransportCmd: Recv-msg raw_data_size is too large: 0x%x." % raw_data_size)

        cursize = 0x4
        tmp_types = struct.unpack('<BBBB', msg[pos:pos+cursize])
        pos+= cursize
        cursize = 0x10
        tmp_sizes = struct.unpack('<IIII', msg[pos:pos+cursize])
        pos+= cursize

        for i in range(4):
            if i < len(self.buffer_types):
                self.buffer_types[i] = tmp_types[i]
                self.buffer_sizes[i] = tmp_sizes[i]

        cursize = raw_data_size<<2
        self.rawdata = msg[pos:pos+cursize]
        pos+= cursize

        if not noprint:
            print "Raw msg reply:"
            print hexdump(msg)
            print "Rawdata payload:"
            print hexdump(self.rawdata[0x4:])
            print "Retval: 0x%x" % self.recv_ret
        self.recv_ret = struct.unpack('<I', self.rawdata[0x0:0x0+0x4])[0]

        for i in range(4):
            if i < len(self.buffer_types):
                self.buffers[i] = ''
                if self.buffer_types[i]==1: # To host
                    self.buffers[i] = c.read_device(self.buffer_sizes[i])

    def execute(self, c, noprint=False):
        self._send_cmd(c)
        self._recv_cmd(c, noprint)

        return {
            "rc": self.recv_ret,
            "raw": self.rawdata[0x4:],
            "buffers": self.buffers
        }

class Client():
    def __init__(self, servaddr=""):
        if servaddr!="":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((servaddr, 56123))
            self.sock_setup = True
            return

        self.sock_setup = False

        # find our device
        self.dev = usb.core.find(idVendor=0x057e, idProduct=0x3000)

        # was it found?
        if self.dev is None:
            raise ValueError('Device not found')

        # set the active configuration. With no arguments, the first
        # configuration will be the active one
        self.dev.set_configuration()

        # get an endpoint instance
        self.cfg = self.dev.get_active_configuration()
        self.intf = usb.util.find_descriptor(self.cfg, bInterfaceClass=0xff, bInterfaceSubClass=0xff, bInterfaceProtocol=0xfe)

        self.ep_in = usb.util.find_descriptor(
            self.intf,
            # match the first IN endpoint
            custom_match = \
            lambda e: \
                usb.util.endpoint_direction(e.bEndpointAddress) == \
                usb.util.ENDPOINT_IN)

        assert self.ep_in is not None

        self.ep_out = usb.util.find_descriptor(
            self.intf,
            # match the first OUT endpoint
            custom_match = \
            lambda e: \
                usb.util.endpoint_direction(e.bEndpointAddress) == \
                usb.util.ENDPOINT_OUT)

        assert self.ep_out is not None

    #def __del__(self):
        #os.close(self.devicef)

    def read_device_partial(self, size):
        if self.sock_setup:
            tmp_data = self.sock.recv(size)
            if not tmp_data:
                return ''
            return tmp_data

        tmp_data = self.ep_in.read(size, 1000*10)
        tmp_data = ''.join([chr(x) for x in tmp_data])
        return tmp_data

    def read_device(self, size):
        data = ""

        while size != 0:
            #tmp_data = os.read(self.devicef, size)
            if self.sock_setup:
                tmp_data = self.sock.recv(size)
                if not tmp_data or tmp_data=='':
                    return ''
            else:
                tmp_data = self.ep_in.read(size, 1000*10)
                tmp_data = ''.join([chr(x) for x in tmp_data])
            size -= len(tmp_data)
            data+= tmp_data
        return data

    def write_device(self, data):
        size = len(data)
        tmplen = 0;

        if self.sock_setup:
            self.sock.sendall(data)
            return

        while size != 0:
            #tmplen = os.write(self.devicef, data)
            tmplen = self.ep_out.write(data)
            size -= tmplen
            data = data[tmplen:]

    def transport_cmd(self, _id,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF, f=0xFFFFFFFFFFFFFFFF, noprint=False):
        cmd = TransportCmd(_id)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        cmd.add_raw_64(d)
        cmd.add_raw_64(e)
        cmd.add_raw_64(f)
        return cmd.execute(self, noprint)

    def transport_cmd_noprint(self, _id,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF, f=0xFFFFFFFFFFFFFFFF):
        return self.transport_cmd(_id, a, b, c, d, e, f, True)

    def transport_cmd_inbuf(self, _id, buf,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF, f=0xFFFFFFFFFFFFFFFF, noprint=False):
        cmd = TransportCmd(_id)
        cmd.add_sendbuf(buf)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        cmd.add_raw_64(d)
        cmd.add_raw_64(e)
        cmd.add_raw_64(f)
        return cmd.execute(self, noprint)

    def transport_cmd_inbuf_noprint(self, _id, buf,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF, f=0xFFFFFFFFFFFFFFFF):
        return self.transport_cmd_inbuf(_id, buf, a, b, c, d, e, f, True)

    def transport_cmd_outbuf(self, _id, size,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF, f=0xFFFFFFFFFFFFFFFF, noprint=False):
        cmd = TransportCmd(_id)
        cmd.add_recvbuf(size)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        cmd.add_raw_64(d)
        cmd.add_raw_64(e)
        cmd.add_raw_64(f)
        return cmd.execute(self, noprint)

    def transport_cmd_outbuf_noprint(self, _id, size,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF, f=0xFFFFFFFFFFFFFFFF):
        return self.transport_cmd_outbuf(_id, size, a, b, c, d, e, f, True)

    def transport_cmd_inbuf_outbuf(self, _id, buf0, size1,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF, f=0xFFFFFFFFFFFFFFFF, noprint=False):
        cmd = TransportCmd(_id)
        cmd.add_sendbuf(buf0)
        cmd.add_recvbuf(size1)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        cmd.add_raw_64(d)
        cmd.add_raw_64(e)
        cmd.add_raw_64(f)
        return cmd.execute(self, noprint)

    def transport_cmd_inbuf_inbuf_inbuf(self, _id, buf0, buf1, buf2,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF, f=0xFFFFFFFFFFFFFFFF, noprint=False):
        cmd = TransportCmd(_id)
        cmd.add_sendbuf(buf0)
        cmd.add_sendbuf(buf1)
        cmd.add_sendbuf(buf2)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        cmd.add_raw_64(d)
        cmd.add_raw_64(e)
        cmd.add_raw_64(f)
        return cmd.execute(self, noprint)

    def transport_cmd_inbuf_inbuf_outbuf(self, _id, buf0, buf1, size2,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF, f=0xFFFFFFFFFFFFFFFF, noprint=False):
        cmd = TransportCmd(_id)
        cmd.add_sendbuf(buf0)
        cmd.add_sendbuf(buf1)
        cmd.add_recvbuf(size2)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        cmd.add_raw_64(d)
        cmd.add_raw_64(e)
        cmd.add_raw_64(f)
        return cmd.execute(self, noprint)

    def stream_data(self, filepath):
        file_out = open(filepath, 'wb')
        while 1:
            tmp_data = self.read_device_partial(0x200)
            if len(tmp_data) == 0:
                continue

            file_out.write(tmp_data)
            file_out.flush()
            os.fsync(file_out.fileno())
        file_out.close()

    def maps(self):
        cur = 0
        while cur < 2 ** 64:
            queryout = self.transport_cmd_noprint(5, cur)['raw'][0x8:]
            pageinfo, base, size, state, perm = struct.unpack('<QQQQI', queryout[:0x24])
            pageinfo = pageinfo & 0xFFFFFFFF
            s = "Base: 0x{:016x} | Size: 0x{:016x} | Perm: {} | State: 0x{:x} | Pageinfo: 0x{:x}".format(base, size, perm_to_str(perm), state, pageinfo)
            print s

            cur += size

    def debug_process(self, pid):
        res = self.transport_cmd_noprint(9, pid)
        if res['rc'] != 0:
            raise Exception("Cmd failed: 0x%x" % res['rc'])
        ret = struct.unpack('<I', res['raw'][0x0:0x0+0x4])[0]
        if ret != 0:
            raise Exception("svcDebugActiveProcess failed: 0x%x" % ret)
        return struct.unpack('<I', res['raw'][0x8:0x8+0x4])[0]

    def debug_maps(self, debughandle):
        cur = 0
        while cur < 2 ** 64:
            queryout = self.transport_cmd_noprint(10, debughandle, cur)['raw'][0x8:]
            pageinfo, base, size, state, perm = struct.unpack('<QQQQI', queryout[:0x24])
            pageinfo = pageinfo & 0xFFFFFFFF
            s = "Base: 0x{:016x} | Size: 0x{:016x} | Perm: {} | State: 0x{:x} | Pageinfo: 0x{:x}".format(base, size, perm_to_str(perm), state, pageinfo)
            print s

            cur += size

    def debug_readmem(self, debughandle, addr, size):
        res = self.transport_cmd_outbuf_noprint(11, size, debughandle, addr)
        if res['rc'] != 0:
            raise Exception("Cmd failed: 0x%x" % res['rc'])
        ret = struct.unpack('<I', res['raw'][0x0:0x0+0x4])[0]
        if ret != 0:
            raise Exception("svcReadDebugProcessMemory failed: 0x%x" % ret)
        return res['buffers'][0]

    def debug_writemem(self, debughandle, addr, data):
        res = self.transport_cmd_inbuf_noprint(34, data, debughandle, addr)
        if res['rc'] != 0:
            raise Exception("Cmd failed: 0x%x" % res['rc'])
        ret = struct.unpack('<I', res['raw'][0x0:0x0+0x4])[0]
        if ret != 0:
            raise Exception("svcWriteDebugProcessMemory failed: 0x%x" % ret)
        return 0

    def debug_pid_maps(self, pid):
        debughandle = self.debug_process(pid)
        self.debug_maps(debughandle)
        self.svcCloseHandle(debughandle)

    def debug_pid_readmem(self, pid, addr, size):
        debughandle = self.debug_process(pid)
        try:
            data = self.debug_readmem(debughandle, addr, size)
        finally:
            self.svcCloseHandle(debughandle)
        return data

    def debug_pid_writemem(self, pid, addr, data):
        debughandle = self.debug_process(pid)
        try:
            out = self.debug_writemem(debughandle, addr, data)
        finally:
            self.svcCloseHandle(debughandle)
        return out

    def debug_pid_readmem_dumpfile(self, pid, addr, size, filepath, chunksize=0x100000):
        tmpf = open(filepath, 'wb')
        debughandle = self.debug_process(pid)
        while size!=0:
            sz = chunksize
            if size < sz:
                sz = size

            try:
                data = self.debug_readmem(debughandle, addr, sz)
            except:
                self.svcCloseHandle(debughandle)
                raise

            tmpf.write(data)
            addr+= sz
            size-= sz
        self.svcCloseHandle(debughandle)
        tmpf.close()

    def svcCloseHandle(self, handle):
        return self.transport_cmd_noprint(13, handle)

    def svcGetProcessList(self):
        res = self.transport_cmd_outbuf_noprint(18, 0x1000)
        if res['rc'] != 0:
            raise Exception("Cmd failed: 0x%x" % res['rc'])
        pidcount = struct.unpack('<I', res['raw'][0x0:0x0+0x4])[0]

        pids = []
        for i in range(pidcount):
            pids.append(struct.unpack('<Q', res['buffers'][0][i*8:i*8+8])[0])
        return pids

    def getservice(self, name):
        servname = 0
        for i in range(8):
            if i < len(name):
                servname |= ord(name[i]) << (i*8)
        res = self.transport_cmd_noprint(16, servname)
        if res['rc'] != 0:
            raise Exception("Cmd failed: 0x%x" % res['rc'])
        return struct.unpack('<I', res['raw'][0x0:0x0+0x4])[0]

    def fs_getservsession(self):
        res = self.transport_cmd_noprint(17)
        if res['rc'] != 0:
            raise Exception("Cmd failed: 0x%x" % res['rc'])
        return struct.unpack('<I', res['raw'][0x0:0x0+0x4])[0]

    def fs_dumpistorage(self, istorage_handle, file_out, off=0, endsize=0, sz=0x8000):
        reloff = 0

        if endsize==0:
            res = self.cmd_fast(istorage_handle, 4)
            rc = res['rc']
            if rc != 0:
                raise Exception('GetSize failed: 0x%x' % rc)
            endsize = struct.unpack('<Q', res['raw'][0x10:0x10+0x8])[0]
            print "Using storage size: 0x%x" % endsize
            endsize-= off
            print "Using endsize: 0x%x" % endsize

        file_out = open(file_out, 'wb')
        while True:
            if endsize-reloff < sz:
                sz = endsize-reloff
            res = self.cmd_buf46(istorage_handle, 0, '', sz, off, sz, 0xFFFFFFFFFFFFFFFF, True)
            rc = res['rc']
            if rc != 0:
                file_out.close()
                raise Exception('Unknown error 0x%x' % rc)

            file_out.write(res['buffers'][0])
            off += sz
            reloff += sz
            if endsize!=0 and reloff >= endsize:
                print 'Reached end-off OK!'
                break
        file_out.close()

    def acc_GetActiveUser(self):
        res = self.transport_cmd(25, 0, 0, 0, 0, 0, 0, True)
        if res['rc'] != 0:
            raise Exception("Cmd failed: 0x%x" % res['rc'])
        tmp = struct.unpack('<QQB', res['raw'][:0x11])
        return {
            'userid': tmp[0] | (tmp[1]<<64),
            'userid_low': tmp[0],
            'userid_high': tmp[1],
            'account_selected': tmp[2],
        }

    def fs_mount_save(self, device, saveid, userid_low, userid_high, savetype=0): # savetype 0 is regular apps, 1 for SystemSaveData.
        return self.transport_cmd_inbuf(26, "%s\0" % device, saveid, userid_low, userid_high, savetype)['rc']

    def fs_device_unmount(self, device):
        return self.transport_cmd_inbuf(27, "%s\0" % device)['rc']

    def fs_device_commit(self, device):
        return self.transport_cmd_inbuf(28, "%s\0" % device)['rc']

    def fs_dirlist(self, fspath, outsize):
        res = self.transport_cmd_inbuf_outbuf(29, "%s\0" % fspath, outsize, 0, 0, 0, 0, 0, 0, True)
        if res['rc'] != 0:
            raise Exception("Cmd failed: 0x%x" % res['rc'])
        actual_size = struct.unpack('<Q', res['raw'][0x0:0x0+8])[0]
        entrysize = struct.unpack('<Q', res['raw'][0x8:0x8+8])[0]
        data = res['buffers'][1][:actual_size]
        dirlist = []

        if actual_size >= entrysize:
            for pos in range(actual_size / entrysize):
                tmp_pos = pos * entrysize
                entryname = data[tmp_pos+0x3:tmp_pos+0x3+0x101]
                endpos = entryname.find('\0')
                if endpos != -1:
                    entryname = entryname[:endpos]
                entrytype = struct.unpack('<B', data[tmp_pos+0x2:tmp_pos+0x2+1])[0]

                entrydata = {
                    'name': entryname,
                    'type': entrytype == 8
                }
                dirlist.append(entrydata)

        return dirlist

    def fs_ls(self, fspath, outsize=0x100000):
        dirlist = self.fs_dirlist(fspath, outsize)
        print "total %u" % (len(dirlist))

        for entry in dirlist:
            tmptype = 'd'
            if entry['type'] == True:
                tmptype = '-'

            try:
                tmp_stat = self.fs_stat("%s/%s" % (fspath, entry['name']))
                tmp_size = "%u" % (tmp_stat['size'])
            except:
                tmp_size = '-'
                pass

            print "%s %s %s" % (tmptype, tmp_size, entry['name'])

    def fs_stat(self, fspath):
        res = self.transport_cmd_inbuf(30, "%s\0" % fspath, 0, 0, 0, 0, 0, 0, True)
        if res['rc'] != 0:
            raise Exception("Cmd failed: 0x%x" % res['rc'])

        tmptype = struct.unpack('<I', res['raw'][0x4:0x4+4])[0] & 0170000

        return {
            'size': struct.unpack('<Q', res['raw'][0x10:0x10+8])[0],
            'type': tmptype == 0100000, # is-file
        }

    def fs_stdio_rwfile(self, fspath, host_path, rw_flag, off=0, endsize=0, sz=0x8000):
        reloff = 0

        if endsize==0:
            if rw_flag==False:
                endsize = self.fs_stat(fspath)['size']
            if rw_flag==True:
                endsize = os.path.getsize(host_path)
            print "Using file size: 0x%x" % endsize
            endsize-= off
            print "Using endsize: 0x%x" % endsize

        fspath = "%s\0" % fspath

        tmp_mode = 'rb'
        fsmode = 'wb\0'
        fsmode2 = 'r+b\0'
        if rw_flag==False:
            tmp_mode = 'wb'
            fsmode = 'rb\0'
            fsmode2 = 'rb\0'
        host_file = open(host_path, tmp_mode)
        if rw_flag==True:
            host_file.seek(off)

        while True:
            if endsize-reloff < sz:
                sz = endsize-reloff

            if off != 0:
                fsmode = fsmode2

            if rw_flag==False:
                res = self.transport_cmd_inbuf_inbuf_outbuf(31, fspath, fsmode, sz, off, 0, 0, 0, 0, 0, True)
            if rw_flag==True:
                tmpdata = host_file.read(sz)
                res = self.transport_cmd_inbuf_inbuf_inbuf(31, fspath, fsmode, tmpdata, off, 1, 0, 0, 0, 0, True)
            rc = res['rc']
            if rc != 0:
                host_file.close()
                raise Exception('Unknown error 0x%x' % rc)

            actual_size = struct.unpack('<Q', res['raw'][:0x8])[0]

            if rw_flag==False:
                host_file.write(res['buffers'][2][:actual_size])

            off += actual_size
            reloff += actual_size
            if endsize!=0 and reloff >= endsize:
                print 'Reached end-off OK!'
                break
        host_file.close()

    def fs_unlink(self, fspath):
        return self.transport_cmd_inbuf(32, "%s\0" % fspath)['rc']

    def launch_hb(self, path='hax.nsp', titleid=0x0100133333370000, storageid=3, launchtitle=1):
        lrh = self.getservice('lr')
        lrh0 = self.cmd(lrh, 0, storageid)["handles"][0]

        self.cmd_buf9(lrh0, 1, "@Sdcard:/%s\0" % path, 0x300, titleid)

        self.svcCloseHandle(lrh)
        self.svcCloseHandle(lrh0)

        if launchtitle==1:
            pmshell = self.getservice('pm:shell')
            c.cmd(pmshell, 0, 0x31, titleid, storageid)
            c.svcCloseHandle(pmshell)
        c.svcCloseHandle(lrh)
        c.svcCloseHandle(lrh0)

    # 'buf' params for input buffers are the actual python buffer data(not addrs), while for output buffers these are unused. Output buffers can be accessed via res['buffers'].
    def cmd(self, h, _id,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF, f=0xFFFFFFFFFFFFFFFF, fast=False):
        cmd = IpcCmd(_id)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        cmd.add_raw_64(d)
        cmd.add_raw_64(e)
        cmd.add_raw_64(f)
        return cmd.execute(self, h, fast)

    def cmd_rawdata50(self, h, _id,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF, f=0xFFFFFFFFFFFFFFFF, 
            g=0xFFFFFFFFFFFFFFFF, _h=0xFFFFFFFFFFFFFFFF, 
            i=0xFFFFFFFFFFFFFFFF, j=0xFFFFFFFFFFFFFFFF, fast=False):
        cmd = IpcCmd(_id)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        cmd.add_raw_64(d)
        cmd.add_raw_64(e)
        cmd.add_raw_64(f)
        cmd.add_raw_64(g)
        cmd.add_raw_64(_h)
        cmd.add_raw_64(i)
        cmd.add_raw_64(j)
        return cmd.execute(self, h, fast)

    def cmd_fast(self, h, _id,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF, f=0xFFFFFFFFFFFFFFFF):
        return self.cmd(h, _id, a, b, c, d, e, f, True)

    def cmd_buf6(self, h, _id, buf, size,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF):
        cmd = IpcCmd(_id)
        cmd.add_4_2(buf, size)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        return cmd.execute(self, h)

    def cmd_buf46(self, h, _id, buf, size,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, fast=False):
        cmd = IpcCmd(_id)
        cmd.add_40_4_2(buf, size)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        return cmd.execute(self, h, fast)

    def cmd_pid_buf46(self, h, _id, buf, size,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF):
        cmd = IpcCmd(_id)
        cmd.send_pid()
        cmd.add_40_4_2(buf, size)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        cmd.add_raw_64(d)
        cmd.add_raw_64(e)
        return cmd.execute(self, h)

    def cmd_buf46_raw5(self, h, _id, buf, size,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF, fast=False):
        cmd = IpcCmd(_id)
        cmd.add_40_4_2(buf, size)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        cmd.add_raw_64(d)
        cmd.add_raw_64(e)
        return cmd.execute(self, h, fast)

    def cmd_buf86(self, h, _id, buf, size,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF):
        cmd = IpcCmd(_id)
        cmd.add_80_4_2(buf, size)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        return cmd.execute(self, h)

    def cmd_buf5(self, h, _id, buf, size,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF):
        cmd = IpcCmd(_id)
        cmd.add_4_1(buf, size)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        return cmd.execute(self, h)

    def cmd_buf5_buf5_raw5(self, h, _id, buf, size, buf2, size2,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF):
        cmd = IpcCmd(_id)
        cmd.add_4_1(buf, size)
        cmd.add_4_1(buf2, size2)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        cmd.add_raw_64(d)
        cmd.add_raw_64(e)
        return cmd.execute(self, h)

    def cmd_buf9(self, h, _id, buf, size,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF):
        cmd = IpcCmd(_id)
        cmd.add_8_1(buf, size)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        return cmd.execute(self, h)

    def cmd_buf6_buf6(self, h, _id, buf, size, buf2, size2,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF):
        cmd = IpcCmd(_id)
        cmd.add_4_2(buf, size)
        cmd.add_4_2(buf2, size2)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        return cmd.execute(self, h)

    def cmd_buf5_buf6_buf6(self, h, _id, buf, size, buf2, size2, buf3, size3,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF):
        cmd = IpcCmd(_id)
        cmd.add_4_1(buf, size)
        cmd.add_4_2(buf2, size2)
        cmd.add_4_2(buf3, size3)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        return cmd.execute(self, h)

    def cmd_buf5_buf6(self, h, _id, buf, size, buf2, size2,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, sendpid=False):
        cmd = IpcCmd(_id)
        if sendpid==True:
            cmd.send_pid()
        cmd.add_4_1(buf, size)
        cmd.add_4_2(buf2, size2)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        return cmd.execute(self, h)

    def cmd_buf5_buf6_raw5(self, h, _id, buf, size, buf2, size2,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF):
        cmd = IpcCmd(_id)
        cmd.add_4_1(buf, size)
        cmd.add_4_2(buf2, size2)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        cmd.add_raw_64(d)
        cmd.add_raw_64(e)
        return cmd.execute(self, h)

    def cmd_bufa_buf9_raw5(self, h, _id, buf, size, buf2, size2,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF):
        cmd = IpcCmd(_id)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        cmd.add_raw_64(d)
        cmd.add_raw_64(e)
        cmd.add_8_1(buf2, size2)
        cmd.add_8_2(buf, size)
        return cmd.execute(self, h)

    def cmd_bufa_buf9_raw4_raw32(self, h, _id, buf, size, buf2, size2,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF):
        cmd = IpcCmd(_id)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        cmd.add_raw_64(d)
        cmd.add_raw_32(e)
        cmd.add_8_2(buf, size)
        cmd.add_8_1(buf2, size2)
        return cmd.execute(self, h)

    def cmd_bufa_raw5(self, h, _id, buf, size, 
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF,
            e=0xFFFFFFFFFFFFFFFF):
        cmd = IpcCmd(_id)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        #cmd.add_raw_64(c)
        #cmd.add_raw_64(d)
        #cmd.add_raw_64(e)
        cmd.add_8_2(buf, size)
        return cmd.execute(self, h)

    def cmd_handle(self, h, _id, handle,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF):
        cmd = IpcCmd(_id)
        cmd.add_handle(handle)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        return cmd.execute(self, h)

    def cmd_pid_handle(self, h, _id, handle,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF):
        cmd = IpcCmd(_id)
        cmd.send_pid()
        cmd.add_handle(handle)
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        return cmd.execute(self, h)

    def cmd_pid(self, h, _id,
            a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF,
            c=0xFFFFFFFFFFFFFFFF, d=0xFFFFFFFFFFFFFFFF):
        cmd = IpcCmd(_id)
        cmd.send_pid()
        cmd.add_raw_64(a)
        cmd.add_raw_64(b)
        cmd.add_raw_64(c)
        cmd.add_raw_64(d)
        return cmd.execute(self, h)

nxsm_auth = open('data/auth.bin', 'rb').read(0x20)
if len(nxsm_auth) != 0x20:
    print "Invalid nxsm_auth size."
    sys.exit(1)

if __name__ == "__main__":
    import code
    print '== Switch sysmodule RPC Client =='
    print ''

    servaddr = ''
    if len(sys.argv) > 1:
        servaddr = sys.argv[1]

    c = Client(servaddr)
    code.interact('', local=locals())

