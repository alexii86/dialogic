#include "stdafx.h"
#include <stdio.h>
//---------------------------------------------------------------------------
#ifdef _WIN32
#define LINT_ARGS
#endif

extern "C" {
#include "C:\DSI\INC\msg.h"
#include "C:\DSI\INC\sysgct.h"
#include "C:\DSI\INC\strtonum.h"
};

#ifdef _WIN32
#pragma comment (lib, "gctlib.lib")
#endif

//---------------------------------------------------------------------------
#define CLI_EXIT_REQ            -1    /* Option requires immediate exit */
#define CLI_UNRECON_OPTION      -2    /* Unrecognised option */
#define CLI_RANGE_ERR           -3    /* Option value is out of range */
//---------------------------------------------------------------------------
int  moduleID=0;

void ShowSyntax() {
	printf("gcrgrab. (Build 1)\n");
	printf("Extracts all messages for specified ModuleID from GCT queue and send to stdout\n\n");
	printf("Syntax: gcrgrab.exe -m<module id>\n");
	printf(" -m : modile ID \n");
}

int readOption(char *arg) {
	u32 temp_u32;

	if (arg[0] != '-')
		return(CLI_UNRECON_OPTION);

	switch (arg[1])
	{
	case 'h' :
	case 'H' :
	case '?' :
	case 'v' :
		ShowSyntax();
		return(CLI_EXIT_REQ);

	case 'm' :
		if (!strtonum(&temp_u32, &arg[2]))
			return(CLI_RANGE_ERR);
		moduleID = (u8)temp_u32;
		break;
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

	for (i=1; i < argc; i++)
	{
		if ((error = readOption(argv[i])) != 0)
		{
			*arg_index = i;
			return(error);
		}
	}
	return(0);
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
			fprintf(stderr,"Unrecognised option:%s\n", argv[failed_arg]);
			ShowSyntax();
			break;
		case CLI_RANGE_ERR:
			fprintf(stderr,"Parameter range error:%s\n", argv[failed_arg]);
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

	HDR   *hdr;
	MSG   *m;

	while ((hdr = GCT_grab(moduleID))!=NULL) {
		m = (MSG *)hdr;
		unsigned int instance = GCT_get_instance(hdr);
		const int strBufSize = 128;
		char strHeader[strBufSize];
		snprintf(strHeader, strBufSize, "M-I%04x-t%04x-i%04x-f%02x-d%02x-s%02x", instance, hdr->type, hdr->id, hdr->src, hdr->dst, hdr->status);
		if (m->len == 0) {
			printf("%s\n", strHeader);
		} else {
			char *strParam = new char[m->len*2 + 1];
			unsigned char *buf = (unsigned char *)m->param;
			for(int i=0; i < m->len; i++)
				snprintf(strParam + i*2, 2, "%02x", buf[i]);
			strParam[m->len*2] = 0;
			printf("%s-p(%d)%s\n", strHeader, m->len, strParam);
		}
		relm(hdr);
	}
	return 0;
}
