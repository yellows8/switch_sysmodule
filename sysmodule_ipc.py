import struct

from sysmodule_client import *

class IpcCmd:
    def __init__(self, cmdid):
        self.transport_cmd = TransportCmd(15)
        self.buf_types = []
        self.handles = []
        self.pid = False
        self.type = 4

        self.raw = ''
        self.add_raw_64(0x49434653)
        self.add_raw_64(cmdid)

        self.recv_handles = []

    def add_raw_64(self, val):
        self.raw += struct.pack('<Q', val)
    def add_raw_32(self, val):
        self.raw += struct.pack('<I', val)
    def add_handle(self, h):
        self.handles.append(h)
    def send_pid(self):
        self.pid = True

    def _add_ab(self, buf, size, flags, type):
        if type == 'a':
            self.buf_types.append((flags<<4) | 1)
            self.transport_cmd.add_sendbuf(buf)
        else:
            self.buf_types.append((flags<<4) | 2)
            self.transport_cmd.add_recvbuf(size)

    def _add_x(self, buf, size):
            self.buf_types.append((0<<4) | 4)
            self.transport_cmd.add_sendbuf(buf)

    def _add_c(self, buf, size): # Must be called after all other add_raw* calls.
            self.buf_types.append((0<<4) | 5)
            self.transport_cmd.add_recvbuf(size)

    def add_4_1(self, buf, size):
        return self._add_ab(buf, size, 0, 'a')
    def add_40_4_1(self, buf, size):
        return self._add_ab(buf, size, 1, 'a')
    def add_80_4_1(self, buf, size):
        return self._add_ab(buf, size, 3, 'a')
    def add_4_2(self, buf, size):
        return self._add_ab(buf, size, 0, 'b')
    def add_40_4_2(self, buf, size):
        return self._add_ab(buf, size, 1, 'b')
    def add_80_4_2(self, buf, size):
        return self._add_ab(buf, size, 3, 'b')

    def add_8_1(self, buf, size):
        return self._add_x(buf, size)

    def add_8_2(self, buf, size):
        return self._add_c(buf, size)

    def set_type(self, t):
        self.type = t

    def _construct(self, h):
        msg = ''

        msg += struct.pack('<I', h)

        extra = 0
        if (len(self.handles) > 0) or self.pid:
            extra = 1 if self.pid else 0
            extra |= len(self.handles) << 1

        msg += struct.pack('<I', extra)

        if extra != 0:
            if self.pid:
                msg += struct.pack('<II', 0, 0)

            for h in self.handles:
                msg += struct.pack('<I', h)

        if len(self.buf_types) > 4:
            raise Exception("IpcCmd _construct: Too many buffers.")

        type_field = 0

        for i in range(4):
            tmp_type = 0
            if i < len(self.buf_types):
                tmp_type = self.buf_types[i]
            type_field |= tmp_type<<(i*8)

        msg+= struct.pack('<I', type_field)

        return msg + self.raw

    def _dump_response(self, msg, fast=False):
        pos = 4 # Skip reserved session-handle field

        self.pid = None

        handle_desc = struct.unpack('<I', msg[pos+0:pos+4])[0]
        pos += 4

        if handle_desc & 1:
            self.pid = struct.unpack('<Q', msg[pos+0:pos+4])[0]
            pos += 8

        num_handles_copy = (handle_desc >> 1) & 0xF
        num_handles_move = (handle_desc >> 5) & 0xF
        num_handles = num_handles_copy+num_handles_move

        if num_handles!=0:
            if not fast:
                print '__ Handles: ___'
            for i in range(num_handles_copy):
                handle = struct.unpack('<I', msg[pos+0:pos+4])[0]
                pos += 4
                if not fast:
                    print '  [Copied] Handle 0x%x' % handle
                self.recv_handles.append(handle)
            for i in range(num_handles_move):
                handle = struct.unpack('<I', msg[pos+0:pos+4])[0]
                pos += 4
                if not fast:
                    print '  [Moved] Handle 0x%x' % handle
                self.recv_handles.append(handle)

        pos = msg.find('SFCO')
        ret = None

        if pos != -1:
            if not fast:
                print '__ Return ___'
            ret = msg[pos+8 : pos+8+4]
            if len(ret) > 0:
                ret = struct.unpack('<I', ret)[0]
                if not fast:
                    print '0x%x' % ret
            else:
                if not fast:
                    print '(void)'
        self.recv_ret = ret

        self.recv_raw = msg[pos:]

        if not fast:
            print '__ Rawdata: ___'
            print hexdump(self.recv_raw)

    def execute(self, c, h, fast=False):
        self.transport_cmd.rawdata += self._construct(h)
        res = self.transport_cmd.execute(c, True)
        if res['rc']!=0:
            return res

        self._dump_response(res['raw'], fast)
        return {
            "rc": self.recv_ret,
            "handles": self.recv_handles,
            "pid": self.pid,
            "raw": self.recv_raw,
            "buffers": self.transport_cmd.buffers
        }
