#include "mp_white_test.h"

char ThisIsIpAddressInWhitelist ( const char* const string )
{
//	const char* const module = "check_whitelist";

	uint32_t ip;

	if ( StrIp4ToB ( string, &ip ) )
	{
		wl4_t* tmp = white4;

		while ( tmp != 0 )
		{
			if ( ( ip & tmp->m_msk ) ==  tmp->m_net )
			{
//				syslog ( LOG_INFO, "%s: ip: %s is in white list", module, string );
				return 1;
			}

			tmp = tmp->m_next;
		}
	}
	else
	{
		__uint128_t ip6;

		if ( StrIp6ToB ( string, &ip6 ) )
		{
			wl6_t* tmp = white6;

			while ( tmp != 0 )
			{
				if ( ( ip6 & tmp->m_msk ) ==  tmp->m_net )
				{
//					syslog ( LOG_INFO, "%s: ip: %s is in white list", module, string );
					return 1;
				}

				tmp = tmp->m_next;
			}
		}
	}

	return 0;
}
