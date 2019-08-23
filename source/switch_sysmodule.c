#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <switch.h>

#include "auth_bin.h"

extern u32 __start__;

//size_t __nx_heap_size = 0x2000000*2;//Must be a multiple of 0x2000000.

u32 __nx_applet_type = AppletType_None;

#define INNER_HEAP_SIZE 0x300000
size_t nx_inner_heap_size = INNER_HEAP_SIZE;
char   nx_inner_heap[INNER_HEAP_SIZE];

Handle handlelist[3 + 16];
u32 handlelist_types[16] = {0};
s32 server_handles = 3;
s32 handlecount;

Service nvdrv_service;

u32 saved_cmdbuf_count = 0;
u32 saved_cmdbuf[(0x80>>2) * 0x1000];

size_t datalog_size = 0;
size_t datalog_maxsize = 0;
u8 *datalog = NULL;

u32 vi_sessioncount = 0;

FILE *fcmdlog;

static u32 usb_interface=0;

int sock_listenfd = -1, sock_datafd = -1;

#define NXSM_MAGIC 0x4d53584e
#define NXSM_VERSION 1

typedef struct {
	u8 auth[0x20];
	u32 magic;//0x4d53584e 'NXSM'
	u32 version;
	u32 raw_data_size;
	u8 buffer_types[4];//0 = from host, 1 = to host.
	u32 buffer_sizes[4];//Sizes for buffer data sent from/to the host.
	u32 rawdata[0x100>>2];
} transport_msg;

size_t transport_safe_write(void* buffer, size_t size);

void __libnx_initheap(void)
{
	void*  addr = nx_inner_heap;
	size_t size = nx_inner_heap_size;

	// Newlib
	extern char* fake_heap_start;
	extern char* fake_heap_end;

	fake_heap_start = (char*)addr;
	fake_heap_end   = (char*)addr + size;
}

void log_writedata(void* buffer, size_t size)
{
	#ifdef ENABLE_LOGGING
	u8 tmpdata[0x200];
	u8 *bufptr = buffer;
	size_t tmpsize;

	memset(tmpdata, 0, sizeof(tmpdata));
	while(size)
	{
		tmpsize = size;
		if(tmpsize > 0x200)tmpsize = 0x200;	
		memcpy(tmpdata, bufptr, tmpsize);

		if(fwrite(tmpdata, 1, tmpsize, fcmdlog)!=tmpsize)fatalSimple(-2);
		if(fflush(fcmdlog)==-1)fatalSimple(-3);

		size-= tmpsize;
		bufptr+= tmpsize;
	}
	#endif
}

void log_command(IpcParsedCommand *r, u32 session_type, u32 log_data)
{
	size_t tmpsize;
	u32 pos;

	size_t bufsizes[4];

	u32 tmp_cmdbuf[0x80>>2];
	memset(tmp_cmdbuf, 0, sizeof(tmp_cmdbuf));
	memset(bufsizes, 0, sizeof(bufsizes));

	tmp_cmdbuf[0] = session_type;
	memcpy(&tmp_cmdbuf[1], armGetTls(), 0x7c);

	log_writedata(tmp_cmdbuf, 0x80);

	tmpsize = sizeof(r->BufferSizes);

	if(log_data)
	{
		memcpy(bufsizes, r->BufferSizes, sizeof(bufsizes));
		if(r->NumBuffers < sizeof(bufsizes)/sizeof(size_t))
		{
			for(pos=r->NumBuffers; pos<sizeof(bufsizes)/sizeof(size_t); pos++)
			{
				bufsizes[pos] = 0;
			}
		}
	}

	log_writedata(bufsizes, sizeof(bufsizes));

	if(log_data)
	{
		for(pos=0; pos<sizeof(r->BufferSizes)/sizeof(size_t); pos++)
		{
			if(pos>=r->NumBuffers)break;
			if(bufsizes[pos] == 0)continue;

			tmpsize = bufsizes[pos];

			log_writedata(r->Buffers[pos], tmpsize);
		}
	}

	memcpy(armGetTls(), &tmp_cmdbuf[1], 0x7c);
}

Result process_ipc_cmds(IpcParsedCommand *r, u32 *cmdbuf, u32 session_type, u32 cmdid, u32 in_raw_data_insize, u32 *in_raw_data, u32 *out_raw_data, u32 *out_raw_data_count, u32 *stop)
{
	u64 *raw64_in = (u64*)in_raw_data;
	u64 *raw64_out = (u64*)out_raw_data;
	u64 *ptr;
	//u8 *ptr8;
	u32 *ptr32;
	u64 tmpsize;
	u32 pos, pos2, pos3;
	u32 tmpval0, tmpval1;
	u32 skiplog = 0;

	Handle client_handle=0;
	Result ret=0;

	FsFileSystem tmpfs;
	Service tmpserv;

	IpcCommand c;
	ipcInitialize(&c);

	if(session_type)//(outdated comment) 0 = custom port, 1 = vi service session, 2 = IApplicationDisplayService session, 3 = IHOSBinderDriver session.
	{
		if((session_type==2 || session_type==3 || session_type==4) && cmdid==1 && cmdbuf[0x44>>2]==0xc183001b)skiplog=1;
		if(!skiplog)log_command(r, session_type, /*0*/1);

		if(((u16)cmdbuf[0])==0x5)
		{
			if(cmdid!=3 && (cmdid!=2 && cmdid!=4))ret = -1;

			struct {
				u64 magic;
				u64 retval;
				u32 size;
			} *raw;

			if(cmdid==2 || cmdid==4)
			{
				if(R_SUCCEEDED(ret))
				{
					if(handlecount >= sizeof(handlelist)/sizeof(Handle))ret = -2;
				}
				if(R_SUCCEEDED(ret))
				{
					ret = svcCreateSession(&handlelist[handlecount], &client_handle, 0, 0);
					if(R_SUCCEEDED(ret))
					{
						handlelist_types[handlecount - server_handles] = session_type+1;
						handlecount++;
					}
				}

				if(R_SUCCEEDED(ret))ipcSendHandleMove(&c, client_handle);
			}

			raw = ipcPrepareHeader(&c, sizeof(*raw));
			raw->magic = SFCO_MAGIC;
			raw->retval = ret;
			raw->size = 0;

			*((u16*)cmdbuf) = 0;
			log_command(r, session_type, 1);
			return 0;
		}

		if(session_type==1 || session_type==2)
		{
			//log_command(r, session_type | (ipcDispatch(viGetSession_IHOSBinderDriverRelay())<<8), 1);

			struct {
				u64 magic;
				u64 retval;
				u32 zero;
			} *raw;

			ipcSendHandleCopy(&c, 0);
			raw = ipcPrepareHeader(&c, sizeof(*raw));
			raw->magic = SFCO_MAGIC;
			raw->retval = 0;
			raw->zero = 0;

			if(!skiplog)log_command(r, session_type, 1);

			return 0;
		}

		if(session_type==3 || session_type==4)//nvdrv
		{
			if(cmdid==8)
			{
				/*u64 tmp_pid = raw64_in[0];

				struct {
					u64 magic;
					u64 cmd_id;
					u64 pid;
				} *raw;

				raw = ipcPrepareHeader(&c, sizeof(*raw));
				raw->magic = SFCI_MAGIC;
				raw->cmd_id = 7;
				raw->pid = tmp_pid;*/
				svcGetProcessId(&raw64_in[0], CUR_PROCESS_HANDLE);
			}

			ipcDispatch(nvdrv_service.handle);
			if(!skiplog)log_command(r, session_type, 1);

			if(cmdid==3 && r->NumHandles>=2)
			{
				svcCloseHandle(r->Handles[0]);
				svcCloseHandle(r->Handles[0]);
			}

			/*if(cmdid==4)//Can't close this here, this is before reply is sent to user-proc...
			{
				IpcParsedCommand tmp_r;
				ipcParse(&tmpr);
				if(r->NumHandles>=1)svcCloseHandle(r->Handles[0]);
			}*/

			return 0;
		}

		if(session_type==1 || (session_type==2 && cmdid==100))
		{
			ret = 0;
			//if(session_type==1 && cmdid!=0)ret = -1;

			if(session_type==1)
			{
				if(vi_sessioncount)
				{
					//log_command(r, session_type, 0);
					//ipcDispatch(viGetSessionService());
					log_command(r, session_type | (ipcDispatch(viGetSession_IApplicationDisplayService()->handle)<<8), 1);
					return 0;
				}

				vi_sessioncount++;
			}

			struct {
				u64 magic;
				u64 retval;
			} *raw;

			if(R_SUCCEEDED(ret))
			{
				if(handlecount >= sizeof(handlelist)/sizeof(Handle))ret = -2;
			}
			if(R_SUCCEEDED(ret))
			{
				ret = svcCreateSession(&handlelist[handlecount], &client_handle, 0, 0);
				if(R_SUCCEEDED(ret))
				{
					handlelist_types[handlecount - server_handles] = session_type+1;
					handlecount++;
				}
			}

			if(R_SUCCEEDED(ret))ipcSendHandleMove(&c, client_handle);
			raw = ipcPrepareHeader(&c, sizeof(*raw));
			raw->magic = SFCO_MAGIC;
			raw->retval = ret;
		}
		else if(session_type==2 && cmdid!=100)
		{
			ipcDispatch(viGetSession_IApplicationDisplayService()->handle);
		}
		else if(session_type==3)
		{
			ipcDispatch(viGetSession_IHOSBinderDriverRelay()->handle);
		}

		log_command(r, session_type, 1);

		return 0;
	}

	switch(cmdid)
	{
		default:
			return -3;
		break;

		case 0:
			raw64_out[0] = 0x58584148;
			raw64_out[1] = (u64)&__start__;
			*out_raw_data_count = 4;
		break;

		case 1:
			if(in_raw_data_insize < 2)return -4;

			ptr = (u64*)raw64_in[0];
			raw64_out[0] = *ptr;
			*out_raw_data_count = 2;
		break;

		case 2:

			if(in_raw_data_insize < 4)return -4;

			ptr = (u64*)raw64_in[0];
			*ptr = raw64_in[1];
		break;

		case 3:
			if(in_raw_data_insize < 4)return -4;

			raw64_out[0] = svcQueryIoMapping(&raw64_out[1], raw64_in[0], raw64_in[1]);
			*out_raw_data_count = 4;
		break;

		case 4:
			if(in_raw_data_insize < 2)return -4;

			raw64_out[0] = svcQueryPhysicalAddress(&raw64_out[1], raw64_in[0]);
			*out_raw_data_count = 4 * 2;
		break;

		case 5:
			if(in_raw_data_insize < 2)return -4;
			raw64_out[0] = svcQueryMemory((MemoryInfo*)&raw64_out[2], (u32*)&raw64_out[1], raw64_in[0]);
			*out_raw_data_count = 2 * 2 + (0x28>>2);
		break;

		case 6:
			if(in_raw_data_insize < 6)return -4;

			raw64_out[0] = svcGetInfo(&raw64_out[1], raw64_in[0], raw64_in[1], raw64_in[2]);
			*out_raw_data_count = 4 * 2;
		break;

		//Cmd7 old IPC testing code removed.

		//Cmd8 removed.

		case 9:
			if(in_raw_data_insize < 2)return -4;
			raw64_out[0] = svcDebugActiveProcess((Handle*)&raw64_out[1], raw64_in[0]);
			*out_raw_data_count = 4;
		break;

		case 10:
			if(in_raw_data_insize < 4)return -4;
			raw64_out[0] = svcQueryDebugProcessMemory((MemoryInfo*)&raw64_out[2], (u32*)&raw64_out[1], (Handle)raw64_in[0], raw64_in[1]);
			*out_raw_data_count = 2 * 2 + (0x28>>2);
		break;

		case 11:
			if(in_raw_data_insize < 4)return -4;

			if(r->NumBuffers)
			{
				ptr = r->Buffers[0];
				tmpsize = r->BufferSizes[0];
			}
			else
			{
				ptr = &raw64_out[1];
				tmpsize = 0x40;
			}

			raw64_out[0] = svcReadDebugProcessMemory(ptr, (Handle)raw64_in[0], raw64_in[1], tmpsize);

			*out_raw_data_count = 2;
			if(r->NumBuffers==0)*out_raw_data_count += (tmpsize>>2);
		break;

		/*case 12:
			if(in_raw_data_insize < 6)return -4;
			raw64_out[0] = svcContinueDebugEvent((Handle)raw64_in[0], (u32)raw64_in[1], raw64_in[2]);
			*out_raw_data_count = 2;
		break;*/

		case 13:
			if(in_raw_data_insize < 2)return -4;
			raw64_out[0] = svcCloseHandle((Handle)raw64_in[0]);
			*out_raw_data_count = 2;
		break;

		/*case 14://Old removed logging stuff.

		break;*/

		case 15:

			pos = 1;
			if(in_raw_data[pos] & 0x1)ipcSendPid(&c);
			pos2 = (in_raw_data[pos] & 0xf) >> 1;
			pos3 = (in_raw_data[pos] & 0xf) >> 5;
			if(pos2+pos3 > sizeof(c.Handles)/sizeof(Handle))ret = -7;

			if (R_SUCCEEDED(ret)) {
				pos++;
				if(in_raw_data[pos-1] & 0x1)pos+= 2;//PID would go here if this was the reply
				while(pos2) {
					ipcSendHandleCopy(&c, in_raw_data[pos]);
					pos2--;
					pos++;
				}

				while(pos3) {
					ipcSendHandleMove(&c, in_raw_data[pos]);
					pos3--;
					pos++;
				}

				if(r->NumBuffers) {
					for(pos2=0; pos2<r->NumBuffers; pos2++) {
						tmpval0 = (in_raw_data[pos] >> (8*pos2)) & 0x0f;
						tmpval1 = ((in_raw_data[pos] >> (8*pos2)) & 0xf0) >> 4;

						switch(tmpval0)
						{
							default:
								ret = -8;
							break;

							case 1:
								ipcAddSendBuffer(&c, r->Buffers[pos2], r->BufferSizes[pos2], tmpval1);
							break;

							case 2:
								ipcAddRecvBuffer(&c, r->Buffers[pos2], r->BufferSizes[pos2], tmpval1);
							break;

							case 3:
								ipcAddExchBuffer(&c, r->Buffers[pos2], r->BufferSizes[pos2], tmpval1);
							break;

							case 4:
								ipcAddSendStatic(&c, r->Buffers[pos2], r->BufferSizes[pos2], tmpval1);
							break;

							case 5:
								ipcAddRecvStatic(&c, r->Buffers[pos2], r->BufferSizes[pos2], tmpval1);
							break;
						}

						if (R_FAILED(ret)) break;
					}
				}
				pos++;
			}

			if (R_SUCCEEDED(ret)) {

				u32 *raw = ipcPrepareHeader(&c, (in_raw_data_insize-pos)<<2);

				memcpy(raw, &in_raw_data[pos], (in_raw_data_insize-pos)<<2);

				ret = ipcDispatch(in_raw_data[0]);
			}

			IpcParsedCommand tmpr;
			if (R_SUCCEEDED(ret)) {
				ipcParse(&tmpr);

				pos = 0;
				out_raw_data[pos] = 0;//session handle
				pos++;
				pos2 = 0;
				pos3 = 0;
				if(tmpr.HasPid || tmpr.NumHandles)
				{
					ptr32 = armGetTls();//ipc.h doesn't have seperate copy/move handle totals
					out_raw_data[pos] = ptr32[2];

					pos2 = (in_raw_data[pos] & 0xf) >> 1;
					pos3 = (in_raw_data[pos] & 0xf) >> 5;
					if(pos2+pos3 > sizeof(tmpr.Handles))ret = -7;
				}
				else
				{
					out_raw_data[pos] = 0;
				}
				pos++;
			}

			if (R_SUCCEEDED(ret)) {
				memcpy(&out_raw_data[pos], tmpr.Handles, tmpr.NumHandles<<2);
				pos+= tmpr.NumHandles;

				if((tmpr.RawSize>>2)+pos > (0xfc>>2))ret = -7;
			}

			if (R_SUCCEEDED(ret)) {
				memcpy(&out_raw_data[pos], tmpr.Raw, tmpr.RawSize);
				*out_raw_data_count = (tmpr.RawSize>>2)+pos;
			}

			return ret;
		break;

		case 16:
			ret = smGetService(&tmpserv, (char*)in_raw_data);
			if (R_SUCCEEDED(ret)) out_raw_data[0] = tmpserv.handle;
			if (R_SUCCEEDED(ret)) *out_raw_data_count = 1;
			return ret;
		break;

		case 17:
			out_raw_data[0] = fsGetServiceSession()->handle;
			*out_raw_data_count = 1;
			return 0;
		break;

		case 18:
			if(r->NumBuffers==0)return -4;
			ret = svcGetProcessList((u32*)&raw64_out[0], r->Buffers[0], r->BufferSizes[0]>>3);
			*out_raw_data_count = 1;
			return ret;
		break;

		case 19://Only usable when __nx_applet_type isn't set to *None.
			raw64_out[0] = (u64)hidGetSharedmemAddr();
			*out_raw_data_count = 2;
			return 0;

		case 20:
			if(in_raw_data_insize < 4)return -4;

			if(r->NumBuffers)
			{
				ptr = r->Buffers[0];
				tmpsize = r->BufferSizes[0];
			}
			else
			{
				ptr = &raw64_out[1];
				tmpsize = 0x40;
			}

			raw64_out[0] = 1337; memcpy(ptr, (void*)raw64_in[0], tmpsize);

			*out_raw_data_count = 2;
			if(r->NumBuffers==0)*out_raw_data_count += (tmpsize>>2);
		break;
		case 21:
			if(in_raw_data_insize < 4)return -4;

			if(r->NumBuffers)
			{
				ptr = r->Buffers[0];
				tmpsize = r->BufferSizes[0];
			}
			else
			{
				ptr = &raw64_out[1];
				tmpsize = 0x40;
			}

			raw64_out[0] = 1337; memcpy((void*)raw64_in[0], ptr, tmpsize);

			*out_raw_data_count = 2;
		break;

		//Cmd22 removed.

		case 23:
			if(stop)*stop = 0x1;
		break;

		/*case 24://Old removed FS testing stuff.
			
		break;*/

		case 25:
			ret = accountInitialize();
			if(R_FAILED(ret)) return ret;

			ret = accountGetLastOpenedUser((u128*)&raw64_out[0], (bool*)&raw64_out[2]);
			if(R_SUCCEEDED(ret))*out_raw_data_count = 6;
			accountExit();
			return ret;
		break;

		case 26:
			if(in_raw_data_insize < 8)return -4;
			if(r->NumBuffers==0)return -4;

			if(raw64_in[3]==0)
			{
				ret = fsMount_SaveData(&tmpfs, raw64_in[0], *((u128*)&raw64_in[1]));
			}
			else
			{
				ret = fsMount_SystemSaveData(&tmpfs, raw64_in[0]);
			}
			if(R_FAILED(ret)) return ret;

			ret = fsdevMountDevice(r->Buffers[0], tmpfs);
			if(ret!=-1)ret = 0;
			return ret;
		break;

		case 27:
			if(r->NumBuffers==0)return -4;
			return fsdevUnmountDevice(r->Buffers[0]);
		break;

		case 28:
			if(r->NumBuffers==0)return -4;
			return fsdevCommitDevice(r->Buffers[0]);
		break;

		case 29:
			if(r->NumBuffers<2)return -4;

			DIR *d;
			struct dirent *direntry = NULL;

			d = opendir(r->Buffers[0]);
			if(d==NULL)return errno;//-16;

			u8 *tmp_ptr = r->Buffers[1];
			tmpsize = r->BufferSizes[1];
			pos=0;
			while((direntry = readdir(d)))
			{
				if(tmpsize < sizeof(struct dirent))break;

				memcpy(&tmp_ptr[pos], direntry, sizeof(struct dirent));
				pos+= sizeof(struct dirent);
				tmpsize-= sizeof(struct dirent);
			}

			if(closedir(d)!=0)return -17;

			raw64_out[0] = pos;
			raw64_out[1] = sizeof(struct dirent);
			*out_raw_data_count = 4;
			return 0;
		break;

		case 30:
			if(r->NumBuffers==0)return -4;
			struct stat mystat;

			ret = stat(r->Buffers[0], &mystat);
			if(ret!=0)return ret;

			memcpy(&raw64_out[0], &mystat, sizeof(mystat));
			*out_raw_data_count = sizeof(mystat)/4;
			return 0;
		break;

		case 31:
			if(in_raw_data_insize < 4)return -4;
			if(r->NumBuffers < 3)return -4;

			FILE *tmpf;

			tmpf = fopen(r->Buffers[0], r->Buffers[1]);
			if(tmpf==NULL)return -10;

			if(raw64_in[0])
			{
				ret = fseek(tmpf, raw64_in[0], SEEK_SET);
				if(ret==-1)
				{
					fclose(tmpf);
					return -12;
				}
			}

			if(raw64_in[1]==0)
			{
				raw64_out[0] = fread(r->Buffers[2], 1, r->BufferSizes[2], tmpf);
			}
			else
			{
				raw64_out[0] = fwrite(r->Buffers[2], 1, r->BufferSizes[2], tmpf);
			}

			fclose(tmpf);
			*out_raw_data_count = 2;
		break;

		case 32:
			if(r->NumBuffers==0)return -4;
			return unlink(r->Buffers[0]);
		break;

		case 34:
			if(in_raw_data_insize < 4)return -4;

			if(r->NumBuffers)
			{
				ptr = r->Buffers[0];
				tmpsize = r->BufferSizes[0];
			}
			else
			{
				return -4;
			}

			raw64_out[0] = svcWriteDebugProcessMemory((Handle)raw64_in[0], ptr, raw64_in[1], tmpsize);

			*out_raw_data_count = 2;
		break;
	}

	return 0;
}

void process_ipc(u32 *cmdbuf, u32 session_type)
{
	u32 out_wordcount = 2 + 4;
	u32 extra_rawdata_count = 0;
	u32 wordcount=0;
	Result retval=0;
	u32 *rawdata_start = cmdbuf;

	IpcParsedCommand r;

	retval = ipcParse(&r);

	if(R_SUCCEEDED(retval))
	{
		rawdata_start = r.Raw;

		wordcount = r.RawSize;
		retval = process_ipc_cmds(&r, cmdbuf, session_type, rawdata_start[2], wordcount-6, &rawdata_start[4], &cmdbuf[8], &extra_rawdata_count, NULL);
		out_wordcount+= extra_rawdata_count;
	}

	if(session_type)return;

	cmdbuf[0] = 4;//Using libnx ipc for this would be ideal, somehow...
	cmdbuf[1] = out_wordcount & 0x1FF;
	cmdbuf[2] = 0;
	cmdbuf[3] = 0;

	cmdbuf[4] = SFCO_MAGIC;
	cmdbuf[5] = 0;
	cmdbuf[6] = retval;
	cmdbuf[7] = 0;
}

Result process_usb(IpcParsedCommand *r, u32 *rawdata, u32 *raw_data_size, u32 cmdid, u32 *stop)
{
	Result ret=0;
	u32 out_rawdata_size = 0;

	u32 out_rawdata[0xfc>>2];

	memset(out_rawdata, 0, sizeof(out_rawdata));

	ret = process_ipc_cmds(r, NULL, 0, cmdid, *raw_data_size, rawdata, out_rawdata, &out_rawdata_size, stop);

	memcpy(rawdata, out_rawdata, sizeof(out_rawdata));
	*raw_data_size = out_rawdata_size;

	return ret;
}

static void close_socket(int *socket)
{
	if(*socket < 0)return;

	close(*socket);
	*socket = -1;
}

size_t transport_safe_read(void* buffer, size_t size)
{
	u8 *bufptr = buffer;
	size_t cursize=size;
	int tmpsize=0;

	while(cursize)
	{
		if(sock_datafd < 0)
		{
			tmpsize = usbCommsReadEx(bufptr, cursize, usb_interface);
		}
		else
		{
			tmpsize = recv(sock_datafd, buffer, cursize, 0);
		}

		if(sock_datafd >= 0)
		{
			if(tmpsize==0)
			{
				close_socket(&sock_datafd);
				return 0;
			}
			else if(tmpsize==-1)
			{
				if(errno != EWOULDBLOCK && errno != EAGAIN)
				{
					close_socket(&sock_datafd);
					return 0;
				}
				else//blocking
				{
					continue;
				}
			}
		}

		bufptr+= tmpsize;
		cursize-= tmpsize;
	}

	return size;
}

size_t transport_safe_write(void* buffer, size_t size)
{
	u8 *bufptr = buffer;
	size_t cursize=size;
	int tmpsize=0;

	while(cursize)
	{
		if(sock_datafd < 0)
		{
			tmpsize = usbCommsWriteEx(bufptr, cursize, usb_interface);
		}
		else
		{
			tmpsize = send(sock_datafd, buffer, cursize, 0);
		}

		if(sock_datafd >= 0)
		{
			if(tmpsize==0)
			{
				close_socket(&sock_datafd);
				return 0;
			}
			else if(tmpsize==-1)
			{
				if(errno != EWOULDBLOCK && errno != EAGAIN)
				{
					close_socket(&sock_datafd);
					return 0;
				}
				else//blocking
				{
					continue;
				}
			}
		}

		bufptr+= tmpsize;
		cursize-= tmpsize;
	}

	return size;
}

void process_rpc_cmd(u32 *stop)
{
	Result ret=0;
	u32 pos;
	size_t tmp_size=0;
	bool auth_valid = 1;

	transport_msg msg;

	u8 *buffers[4];

	IpcParsedCommand r;

	memset(&r, 0, sizeof(r));
	memset(buffers, 0, sizeof(buffers));

	tmp_size = transport_safe_read(&msg, sizeof(msg));
	if(tmp_size != sizeof(msg))return;
	if(sizeof(msg.auth) != sizeof(msg.auth))return;

	//safe memcmp
	for(pos=0; pos<sizeof(msg.auth); pos++)
	{
		auth_valid &= (msg.auth[pos] == auth_bin[pos]);
	}

	if(!auth_valid)return;
	if(msg.magic != NXSM_MAGIC)return;
	if(msg.version != NXSM_VERSION)return;

	for(pos=0; pos<4; pos++)
	{
		if(msg.buffer_sizes[pos] && (msg.buffer_sizes[pos] & 0x80000000) == 0)
		{
			buffers[pos] = memalign(0x1000, msg.buffer_sizes[pos]);//Page-align for faster data transfer.
			if(buffers[pos])
			{
				memset(buffers[pos], 0, msg.buffer_sizes[pos]);
				if(msg.buffer_types[pos]==0)
				{
					tmp_size = transport_safe_read(buffers[pos], msg.buffer_sizes[pos]);
					if(tmp_size != msg.buffer_sizes[pos])
					{
						free(buffers[pos]);
						buffers[pos] = NULL;
						continue;
					}
				}

				r.Buffers[r.NumBuffers] = buffers[pos];
				r.BufferSizes[r.NumBuffers] = msg.buffer_sizes[pos];
				r.NumBuffers++;
			}
			else
			{
				ret = -3;
				msg.buffer_sizes[pos] = 0;
			}
		}
	}

	if(R_SUCCEEDED(ret))
	{
		if(msg.raw_data_size==0)ret = -1;
	}
	if(R_SUCCEEDED(ret))
	{
		if(msg.raw_data_size > sizeof(msg.rawdata)>>2)ret = -2;
	}

	if(R_SUCCEEDED(ret))
	{
		msg.raw_data_size--;
		msg.rawdata[0] = process_usb(&r, &msg.rawdata[1], &msg.raw_data_size, msg.rawdata[0], stop);
		msg.raw_data_size++;
	}
	else
	{
		msg.rawdata[0] = ret;
		msg.raw_data_size = 1;
	}

	tmp_size = transport_safe_write(&msg, sizeof(msg));
	if(tmp_size != sizeof(msg))return;

	for(pos=0; pos<4; pos++)
	{
		if(buffers[pos])
		{
			if(msg.buffer_types[pos]==1)transport_safe_write(buffers[pos], msg.buffer_sizes[pos]);
			free(buffers[pos]);
		}
	}
}

void rpc_handler(void* arg)
{
	u32 stop=0;
	Result ret=0;
	#ifndef DISABLE_USB
	UsbCommsInterfaceInfo info = {
		.bInterfaceClass = USB_CLASS_VENDOR_SPEC,
		.bInterfaceSubClass = USB_CLASS_VENDOR_SPEC,
		.bInterfaceProtocol = USB_CLASS_APPLICATION,
	};

	usb_interface = 0;

	ret = usbCommsInitializeEx(1, &info);
	if(R_FAILED(ret)) fatalSimple(ret);
	#endif

        sock_listenfd = -1;
        sock_datafd = -1;

	#ifdef DISABLE_USB
	ret = socketInitializeDefault();

	struct sockaddr_in serv_addr;

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(56123);

	if(R_SUCCEEDED(ret))
	{
		sock_listenfd = socket(AF_INET, SOCK_STREAM, 0);

		if(sock_listenfd >= 0)
		{
			int rc = bind(sock_listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
			if(rc == 0)rc = listen(sock_listenfd, 1);
			if(rc != 0)
			{
				close(sock_listenfd);
				sock_listenfd = -1;
			}
		}
	}
	#endif

	while(1)
	{
		#ifdef DISABLE_USB
		if(sock_listenfd >= 0)
		{
			if(sock_datafd < 0)sock_datafd = accept(sock_listenfd, NULL, NULL);
		}

		if(sock_datafd < 0)
		{
			continue;
		}
		#endif

		process_rpc_cmd(&stop);
		if(stop & 0x1)
		{
			while(1)svcSleepThread(1000000000);
		}
	}

	close_socket(&sock_datafd);
	close_socket(&sock_listenfd);

	socketExit();

	#ifndef DISABLE_USB
	usbCommsExit();
	#endif
}

void switch_sysmodule_rpc_initialize()
{
	Result ret=0;
	static Thread rpc_thread;

	ret = threadCreate(&rpc_thread, rpc_handler, 0, 0x4000, 28, -2);
	if (R_FAILED(ret)) fatalSimple(ret);

	ret = threadStart(&rpc_thread);
	if (R_FAILED(ret)) fatalSimple(ret);
}

Result ipc_handler()
{
	Result ret = 0;
	Result ret2 = 0;
	Handle replyTarget=0;
	Handle tmphandle=0;
	s32 handleindex=0;
	s32 tmpindex;
	u32 *cmdbuf = armGetTls();
	s32 pos;

	handlecount = server_handles;

	switch_sysmodule_rpc_initialize();

	#ifdef DISABLE_IPC
	while(1)svcSleepThread(1000000000);
	#endif

	//ret = svcManageNamedPort(&handlelist[0], "hax", 1);
	ret = smRegisterService(&handlelist[0], "hax", false, 1);
	if(R_FAILED(ret))return ret | 8;

	ret = smRegisterService(&handlelist[1], "vilog", false, 10);
	if(R_FAILED(ret))return ret | 12;

	ret = smRegisterService(&handlelist[2], "nvlog", false, 10);
	if(R_FAILED(ret))return ret | 12;

	if(server_handles >= 4)
	{
	ret = smGetService(&nvdrv_service, "nvdrv");
	if(R_FAILED(ret))return ret;

	ret = smUnregisterService("nvdrv");
	if(R_FAILED(ret))return ret;

	ret = smRegisterService(&handlelist[3], "nvdrv", false, 10);
	if(R_FAILED(ret))return ret | 12;
	}

	#ifdef ENABLE_LOGGING
	fcmdlog = fopen("/switch_cmdlog.bin", "wb");
	if(fcmdlog==NULL)fatalSimple(-1);
	#endif

	while(R_SUCCEEDED(ret = svcWaitSynchronization(&handleindex, handlelist, handlecount, U64_MAX)))
	{
		if(handleindex<0 || handleindex>=handlecount)
		{
			ret = -1;
			break;
		}

		if(handleindex < server_handles)
		{
			svcAcceptSession(&tmphandle, handlelist[handleindex]);
			if(handlecount >= sizeof(handlelist)/sizeof(Handle))
			{
				svcCloseHandle(tmphandle);
			}
			else
			{
				handlelist[handlecount] = tmphandle;
				handlelist_types[handlecount - server_handles] = handleindex;
				handlecount++;
			}
		}
		else
		{
			replyTarget = 0;
			tmpindex = handleindex;
			if(R_SUCCEEDED(ret2 = svcReplyAndReceive(&handleindex, &handlelist[tmpindex], 1, replyTarget, U64_MAX)))
			{
				if(handleindex!=0)
				{
					ret = -1;
					break;
				}

				replyTarget = handlelist[tmpindex];

				process_ipc(cmdbuf, handlelist_types[tmpindex - server_handles]);

				ret2 = svcReplyAndReceive(&handleindex, &handlelist[tmpindex], 1, replyTarget, 0);
			}

			if(ret2==0xF601)
			{
				svcCloseHandle(handlelist[tmpindex]);
				handlelist[tmpindex] = 0;
				if(tmpindex+1!=handlecount)
				{
					for(pos=0; pos<handlecount-tmpindex-1; pos++)
					{
						handlelist[pos + tmpindex] = handlelist[pos + tmpindex+1];
						handlelist_types[pos + tmpindex - server_handles] = handlelist_types[pos + tmpindex+1 - server_handles];
					}
				}
				handlecount--;
			}
		}
	}

	return ret | 14;
}

#ifndef ENABLE_SWITCHSYSMODULE
int main(int argc, char **argv)
{
	Result ret=0;

	ret = ipc_handler();

	if(R_FAILED(ret))fatalSimple(ret + (1000<<9));

	return 0;
}
#endif

