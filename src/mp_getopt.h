#ifndef PS_GETOPT_H
#define	PS_GETOPT_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

typedef struct globalArgs_t
{
	char* m_queue_id;
	char* m_client_address;
	char* m_sasl_username;
	char* m_sender;
	int   m_rcpt_argc;
} globalArgs;

extern globalArgs ga;

void GetOpt ( int argc, char** argv );

#endif
