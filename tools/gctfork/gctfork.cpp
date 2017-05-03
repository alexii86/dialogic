#include <stdio.h>
#include <string>
#include <memory.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#else
#include <errno.h> 
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/socket.h> 
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#endif
//---------------------------------------------------------------------------

#ifdef _WIN32
#define LINT_ARGS
#endif

extern "C" {
#include "msg.h"
#include "sysgct.h"
#include "strtonum.h"
};

#ifdef _WIN32
#pragma comment (lib, "gctlib.lib")
#pragma comment(lib,"Ws2_32.lib")
#endif

//---------------------------------------------------------------------------
#define CLI_EXIT_REQ            -1    /* Option requires immediate exit */
#define CLI_UNRECON_OPTION      -2    /* Unrecognised option */
#define CLI_RANGE_ERR           -3    /* Option value is out of range */
//---------------------------------------------------------------------------

using std::string;

int moduleID = 0;
int outputID[2] = {0,0};
int fNetw = 0;
char host[128];
int port;


void ShowSyntax() {
	printf("gctfork. (Build 1)\n");
	printf("Gets messages from input GCT queue and forks them into one or two output queues and/or network socket\n\n");
	printf("Syntax: gctfork.exe -m<input module id> -x<output modile id1> [-y<output modile id2>] [-n<ip_address:port>]\n");
}

int readOption(char *arg) {
	u32 temp_u32;

	if (arg[0] != '-')
		return(CLI_UNRECON_OPTION);

	switch (arg[1])
	{
	case 'h':
	case 'H':
	case '?':
	case 'v':
		ShowSyntax();
		return(CLI_EXIT_REQ);

	case 'm':
		if (!strtonum(&temp_u32, &arg[2]))
			return(CLI_RANGE_ERR);
		moduleID = (u8)temp_u32;
		break;
	case 'x':
		if (!strtonum(&temp_u32, &arg[2]))
			return(CLI_RANGE_ERR);
		outputID[0] = (u8)temp_u32;
		break;
	case 'y':
		if (!strtonum(&temp_u32, &arg[2]))
			return(CLI_RANGE_ERR);
		outputID[1] = (u8)temp_u32;
		break;
	case 'n':
		fNetw = 1;
		int pos = 2;
		int argLen = strlen(arg);
		while ((pos < argLen) && (arg[pos] != ':'))
		{
			host[pos-2] = arg[pos];
			pos++;
		}
		host[pos] = 0x00;
		if (arg[pos] != ':')
			return CLI_RANGE_ERR;
		if ((++pos < argLen) && (strtonum(&temp_u32, &arg[pos])))
			port = temp_u32;
		else
			return CLI_RANGE_ERR;
	}

	return(0);
}
//---------------------------------------------------------------------------
/* Read in command line options a set the system variables accordingly.
*
* Returns 0 on success; on error returns non-zero and
* writes the parameter index which caused the failure
* to the variable arg_index.
*/
int readCLIParameters(int argc, char *argv[], int *arg_index) {
	int error;
	int i;

	for (i = 1; i < argc; i++)
	{
		if ((error = readOption(argv[i])) != 0)
		{
			*arg_index = i;
			return(error);
		}
	}
	return(0);
}

template <typename T>
T swapEndian(T value)
{
	T x=0;
	for (int i = 0; i < sizeof(T); i++)
	{
		int mask = 0xff << i*8;
		x |= ((value & mask) >>i*8) << (sizeof(T) - i - 1)*8;
	}
	return x;
}

/*
 * Ensapsulate Dialogic message into RSI packet
 */
void encodeRSIPacket(HDR *h, char *packet)
{
	// RSI Header
	int pos = 0;
	*((u16 *)(&(packet[pos]))) = swapEndian<u16>(h->type);
	pos += sizeof(u16);
	*((u16 *)(&(packet[pos]))) = swapEndian<u16>(h->id);
	pos += sizeof(u16);
	*((u8 *)(&(packet[pos]))) = h->src;
	pos += sizeof(u8);
	*((u8 *)(&(packet[pos]))) = h->dst;
	pos += sizeof(u8);
	*((u16 *)(&(packet[pos]))) = swapEndian<u16>(h->rsp_req);
	pos += sizeof(u16);
	*((u8 *)(&(packet[pos]))) = h->hclass;
	pos += sizeof(u8);
	*((u8 *)(&(packet[pos]))) = h->status;
	pos += sizeof(u8);
	*((u32 *)(&(packet[pos]))) = swapEndian<u32>(h->err_info);
	pos += sizeof(u32);
	*((u32 *)(&(packet[pos]))) = 0;	// Reserved
	pos += sizeof(u32);

	// Message len field
	MSG *m = (MSG *)h;
	*(reinterpret_cast<u16 *>(&(packet[pos]))) = swapEndian<u16>(m->len);

	// Message content
	memcpy((char *)&(packet[20]), (char *)m->param, m->len);
}

int main(int argc, char* argv[])
{
	int failed_arg;
	int cli_error;

	if ((cli_error = readCLIParameters(argc, argv, &failed_arg)) != 0)
	{
		switch (cli_error)
		{
		case CLI_UNRECON_OPTION:
			fprintf(stderr, "GCTFORK: Unrecognised option:%s\n", argv[failed_arg]);
			ShowSyntax();
			break;
		case CLI_RANGE_ERR:
			fprintf(stderr, "GCTFORK: Parameter range error:%s\n", argv[failed_arg]);
			ShowSyntax();
			break;
		default:
			break;
		}
		return 0;
	}
	if (moduleID == 0) {
		ShowSyntax();
		return 0;
	}
	printf("gctfork started at mod ID=0x%02x, resends to:\n", moduleID);
	//for (int destID : outputID)
	// range-based for is not supported by g++ (GCC) 4.4.7
	for (int i = 0; i < 2; i++)
	{
		if (outputID[i] != 0)
			printf("\tModuleID=0x%02x\n", outputID[i]);
		//if (destID != 0)
		//	printf("\tModuleID=0x%02x\n", destID);
	}
	if (fNetw)
		printf("Resending to network. Host: %s port: %d\n", host, port);
	HDR		*hdr;
	MSG		*m;
	MSG		*newMsg;
#ifdef _WIN32
	SOCKET	sock = INVALID_SOCKET;
#else
	int		sock;
#endif
	struct addrinfo hints, *servinfo = NULL;
	if (fNetw)
	{
#ifdef _WIN32
		// Socket inialization and opening
		WSADATA wsaData;
		int iResult;

		// Initialize Winsock
		iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != 0)
		{
			fprintf( stderr, "GCTFORK: WSAStartup failed with error: %d\n", iResult );
			return 1;
		}

		sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
		if (sock == INVALID_SOCKET)
		{
			fprintf(stderr, "GCTFORK: socket() failed with error: %ld\n", WSAGetLastError() );
			WSACleanup();
			return 1;
		}
#else
		sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock == -1)
		{
			fprintf(stderr, "GCTFORK: socket() failed with error: %ld\n", errno);
			return 1;
		}
#endif

		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		const int strBufSize = 16;
		char sPort[strBufSize];
		snprintf(sPort, strBufSize, "%d", port);
		getaddrinfo(host, sPort, &hints, &servinfo);
	}

	while (1)
	{
		if ((hdr = GCT_receive(moduleID)) != 0)
		{
			m = (MSG *)hdr;
			unsigned int instance = GCT_get_instance(hdr);
			// Resend to destinations
			//for (int destID : outputID)
			// range-based for is not supported by g++ (GCC) 4.4.7
			for (int i = 0; i < 2; i++)
			{
				if (outputID[i] == 0) continue;
				if ((newMsg = getm(hdr->type, 0, 0, m->len)) != 0)
				{
					memcpy((char *)newMsg, (char *)hdr, sizeof(HDR));
					newMsg->len = m->len;
					memcpy((char *)newMsg->param, (char *)m->param, m->len);
					GCT_set_instance(instance, &(newMsg->hdr));
					if (GCT_send(outputID[i], (HDR *)newMsg) != 0) {
						fprintf(stderr, "GCTFORK: GCT_send() error\n");
						relm((HDR *)newMsg);
					}
				}
				else fprintf(stderr, "GCTFORK: getm() error\n");
			}
			// Resend to network
			if (fNetw)
			{
				char packet[sizeof(MSG)];
				encodeRSIPacket(hdr, packet);
				if (sendto(sock, packet, 20 + m->len, 0, servinfo->ai_addr, servinfo->ai_addrlen) == -1)
					fprintf(stderr, "GCTFORK: sendto() error\n");
			}
			relm(hdr);
		}
	}
}
