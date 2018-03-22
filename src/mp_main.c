#include "mp_other.h"

const char* module = "main: ";

void addwl ( const char* ipstr )
{
//	const char* module = "main: ";

	uint32_t ip;
	uint32_t mask;

	if ( StrNet4ToB ( ipstr, &ip, &mask ) )
	{
		uint32_t net = ip & mask;
		AddWhite4 ( net, mask );
	}
	else
	{
		__uint128_t ip6;
		__uint128_t mask6;

		if ( StrNet6ToB ( ipstr, &ip6, &mask6 ) )
		{
			__uint128_t net6 = ip6 & mask6;
			AddWhite6 ( net6, mask6 );
		}
		else
			syslog  (
				LOG_INFO,
				"%s%s: sring: \"%s\" isn't ipv6 or ipv4 addres",
				module,
				ga.m_queue_id,
				ipstr );
	}
}

int main ( int argc, char *argv[] )
{
	struct timespec mt1, mt2;
	clock_gettime ( CLOCK_REALTIME, &mt1 );

	int av_infp;
	pid_t av_stream = popen2 ( MP_AV_CMD, &av_infp );

//	const char* module = "main: ";

	GetOpt ( argc, argv );

/*	printf ( "ga.m_rcpt_argc: %d\n", ga.m_rcpt_argc );
	printf ( "argc: %d\n", argc );
	printf ( "argv[0]: %s\n", argv[0] );
	printf ( "argv[argc]: %s\n", argv[argc] );
	printf ( "argv[ga.m_rcpt_argc]: %s\n", argv[ga.m_rcpt_argc] );*/

	openlog ( MP_LG_TTL, LOG_PID, LOG_MAIL );

	const int add_size = 1048576;
	int buff_fill = 20;
	int buff_size = add_size + buff_fill;
	char* buff = (char*) malloc ( buff_size );
	char* hdr_data = "CLEAN";
	char* hdr_data_old = hdr_data;
	strcpy ( buff, "X-Mailparser: " );
	strncpy ( &buff[14], hdr_data, 5 );
	buff[19] = '\n';

	int buff_max_size = MP_MAX_MSG_SIZE;

	for (;;)
	{
		int read = fread ( &buff[buff_fill], 1, add_size, stdin );

		if ( !read )
			break;

		buff_fill += read ;

		char* tmp_buff = 0;
		int new_buff_size = 0;

		if ( buff_size < buff_max_size )
		{
			new_buff_size = buff_size + add_size;

			if ( new_buff_size > buff_max_size )
				new_buff_size = buff_max_size;

			tmp_buff = (char*) malloc ( new_buff_size );
		}

		if ( !tmp_buff )
		{
			syslog ( LOG_ERR, "%s%s: malloc error", module, ga.m_queue_id );
			break;
		}

		buff_size = new_buff_size;

		memcpy ( tmp_buff, buff, buff_fill );
		free ( buff );
		buff = tmp_buff;
	}

	syslog ( LOG_INFO, "%s%s: client_address: %s", module, ga.m_queue_id, ga.m_client_address );

	char inmynetworks = 0;

	if ( *ga.m_sasl_username == 0 )
	{
// white list
//		addwl ( "192.168.0.6/21" );

		if ( ThisIsIpAddressInWhitelist ( ga.m_client_address ) == 1 )
		{
			syslog ( LOG_INFO, "%s%s: %s in white list", module, ga.m_client_address, ga.m_client_address );
			inmynetworks = 1;
		}
	}

	int rcode = EX_OK;

	if ( rcode == EX_OK )
	{
		int clamav_rc = -1;

		{
			if ( av_stream > 0 )
			{
				if ( buff_fill < MP_AV_STREAM_MAX_LEN && *ga.m_sasl_username == 0 && inmynetworks == 0 )
				{
					fcntl ( av_infp, F_SETFL, O_NONBLOCK );

					for ( ;; )
					{
						int av_rw = write ( av_infp, buff, buff_fill );

						if ( av_rw < 0 )
						{
							syslog ( LOG_ERR, "%s%s: %s: av pipe error", module, ga.m_queue_id, MP_AV_TTL );
						}
						else
						{
							close ( av_infp );
							waitpid ( av_stream, &clamav_rc, 0 );
							break;
						}
					}

					clock_gettime ( CLOCK_REALTIME, &mt2 );
					long double ttt = (1000000000*(mt2.tv_sec - mt1.tv_sec) + (mt2.tv_nsec - mt1.tv_nsec))/1000000000.0;
					syslog ( LOG_INFO, "%s%s: av run time: %Lf seconds", module, ga.m_queue_id, ttt );
				}
				else
				{
					close ( av_infp );
					waitpid ( av_stream, &clamav_rc, 0 );
					clamav_rc = -2;
				}
			}

			switch ( clamav_rc )
			{
			case -2:
				hdr_data_old = "AVNTT";
				break;
			case -1:
				syslog ( LOG_ERR, "%s%s: %s: error", module, ga.m_queue_id, MP_AV_TTL );
				break;
			case 32512:
				syslog ( LOG_ERR, "%s%s: %s: error: command not found", module, ga.m_queue_id, MP_AV_TTL );
				break;
			case 0:
				break;
			case 1:
			case 256:
				syslog ( LOG_WARNING, "%s%s: %s: virus found", module, ga.m_queue_id, MP_AV_TTL );
				hdr_data_old = "VIRUS";
				break;
			}
		}

		// флаг доса
		char sa_dos = '0';

		if ( (argc - ga.m_rcpt_argc)  > MP_MAX_RCPT_NOTDOS || buff_fill > MP_SA_MAX_MSG_SIZE )
		{
			if ( *ga.m_sasl_username == 0 )
			{
				sa_dos = '1';
				syslog ( LOG_WARNING, "%s%s: enable sa anti dos mode MSG_SIZE: %d/%d RCPT: %d/%d", module, ga.m_queue_id, buff_fill, MP_SA_MAX_MSG_SIZE, (argc - ga.m_rcpt_argc), MP_MAX_RCPT_NOTDOS );
			}
		}

		int i = 0;

 		int oldargc = argc;

		int sc_pid[MP_MAX_RCPT];

		for ( i = ga.m_rcpt_argc; i < oldargc; i ++ )
		{
			char* rcpt = argv[i];

			hdr_data = hdr_data_old;

			char cmd_arg[MP_MAX_CMD_LEN] = {0};

			int sr = 0;

			if ( *ga.m_sasl_username == 0 )
			{
				if ( clamav_rc == 1 || clamav_rc == 256 || inmynetworks == 1 )
				{
					// сообщение помечено как вирус - не проверяем в sa
					sr = snprintf (
							cmd_arg,
							sizeof ( cmd_arg ) / sizeof ( *cmd_arg ),
							MP_SM_CMD,
							ga.m_sender,
							argv[i] );
				}
				else
				{
					if ( sa_dos == '0' )
					{
						// обычная рассылка, без доса и авторизации
						sr = snprintf (
								cmd_arg,
								sizeof ( cmd_arg ) / sizeof ( *cmd_arg ),
								MP_SA_CMD,
								argv[i],
								ga.m_sender,
								argv[i] );
					}
					else
					{
						// рассылка с досом, но без авторизации
						char recipient[MP_MAX_RCPT_STR] = {0};

						int j = 0;
						for ( j = ga.m_rcpt_argc; j < argc; j ++ )
						{
							strcat ( recipient, argv[j] );
							if ( j != argc - 1 )
								strcat ( recipient, " " );
						}

						sr = snprintf (
								cmd_arg,
								sizeof ( cmd_arg ) / sizeof ( *cmd_arg ),
								MP_SA_CMD,
								MP_SA_GLOBAL_USER,
								ga.m_sender,
								recipient );

						rcpt = recipient;

						// выход из цикла
						oldargc = ga.m_rcpt_argc;
					}
				}
			}
			else
			{
				//syslog ( LOG_INFO, "%sargv[1]!=0", module );

				// рассылка с авторизацией
				sr = snprintf (
							cmd_arg,
							sizeof ( cmd_arg ) / sizeof ( *cmd_arg ),
							MP_SM_CMD,
							ga.m_sender,
							argv[i] );
			}

			if (  sr > 0 )
			{
				if ( *ga.m_sasl_username != 0 )
				{
					if ( strcmp ( argv[i], ga.m_sasl_username ) == 0 )
					{
						int l;
						int sf = 0;

						for ( l = 0; l < buff_fill - 1; l ++ )
						{
							if ( buff[l] == '\n' )
							{
								if ( buff[l + 1] != '\t' )
								if ( buff[l + 1] != ' ' )
								{
									const char* hdr = &buff[sf];
									buff[l] = 0;

									if ( strstr ( hdr, "To:" ) )
									{
										if ( !strstr ( hdr +4, argv[i] ) )
											hdr_data = "SUBCC";
									}

									buff[l] = '\n';
									sf = l + 1;
								}

								if ( buff[l + 1] == '\n' )
									break;
							}
						}
					}
				}

				strncpy ( &buff[14], hdr_data, 5 );

				syslog ( LOG_INFO,
						"%s%s: msg:%d/%d clamav_rc:%d x-mailparser:%s sa_dos:%c from=<%s> to=<%s> sasl_username=<%s>",
						module,
						ga.m_queue_id,
						(i - ga.m_rcpt_argc + 1),
						oldargc - ga.m_rcpt_argc,
						clamav_rc,
						hdr_data,
						sa_dos,
						ga.m_sender,
						rcpt,
						ga.m_sasl_username );

				int sa_infp;
				pid_t sa_stream = popen2 ( cmd_arg, &sa_infp );

				if ( sa_stream > 0 )
				{
					write ( sa_infp, buff, buff_fill );

					close ( sa_infp );
					sc_pid[i - ga.m_rcpt_argc] = sa_stream;
				}
				else
				{
					syslog ( LOG_ERR, "%s%s: stream = 0", module, ga.m_queue_id );
					rcode = EX_CONFIG;
				}
			}
			else
			{
				rcode = EX_CONFIG;
				syslog ( LOG_ERR, "%s%s: snprintf return <= 0", module, ga.m_queue_id );
			}
		}

		for ( i = 0; i < oldargc - ga.m_rcpt_argc; i ++ )
		{
			int status = 0;

			waitpid ( sc_pid[i], &status, 0 );

			if ( status != 0 )
				syslog ( LOG_ERR, "%s%s: sc_pid[%d]=%d send command return %d", module, ga.m_queue_id, i, sc_pid[i], status );
			else
				syslog ( LOG_INFO, "%s%s: sc_pid[%d]=%d send command return %d", module, ga.m_queue_id, i, sc_pid[i], status );
		}

		free ( buff );
	}

	clock_gettime (CLOCK_REALTIME, &mt2);
	long double tt = (1000000000*(mt2.tv_sec - mt1.tv_sec) + (mt2.tv_nsec - mt1.tv_nsec))/1000000000.0;
	syslog ( LOG_INFO, "%s%s: full run time: %Lf seconds; msg size: %d bytes; ", module, ga.m_queue_id, tt, buff_fill );

	return rcode;
}
