#include "mp_getopt.h"

globalArgs ga = { "NOQUEUEID", "", "", "", 1 };

void GetOpt ( int argc, char** argv )
{
	static const char *optString = "hvs:q:f:a:";

	int opt;

	opt = getopt ( argc, argv, optString );

	while	( opt != -1 )
	{
		switch ( opt )
		{
			case 'h':
				printf ( "Usage:\n-h print help\n-v print version info\n"
							"-f sender\n-s sasl username\n-q queue id\n-a client address\n\n" );
				exit ( 1 );
				break;
			case 'v':
				printf ( "Version: 1.3.5\n" );
				exit ( 1 );
				break;
			case 'q':
					ga.m_queue_id = optarg;
				break;
			case 'f':
					ga.m_sender = optarg;
				break;
			case 's':
					ga.m_sasl_username = optarg;
				break;
			case 'a':
					ga.m_client_address = optarg;
				break;
			case '?':
				exit ( 0 );
				break;
		}

		opt = getopt ( argc, argv, optString );
	}

	ga.m_rcpt_argc = optind;
}
