#include "mp_white.h"

wl4_t* white4 = 0;
wl6_t* white6 = 0;

char AddWhite4 ( uint32_t net, uint32_t mask )
{
	if ( white4 == 0 )
	{
		white4 = malloc ( sizeof ( *white4) );

		if ( white4 != 0 )
		{
			white4->m_net = net;
			white4->m_msk = mask;
			white4->m_next = 0;
		}
	}
	else
	{
		wl4_t* tmp = white4;

		while ( tmp->m_next != 0 )
			tmp = tmp->m_next;

		tmp->m_next = malloc ( sizeof ( *white4) );

		if ( tmp->m_next != 0 )
		{
			tmp->m_next->m_net = net;
			tmp->m_next->m_msk = mask;
			tmp->m_next->m_next = 0;
		}
	}

	return 0;
}

char AddWhite6 ( __uint128_t net, __uint128_t mask )
{
	if ( white6 == 0 )
	{
		white6 = malloc ( sizeof ( *white6) );

		if ( white6 != 0 )
		{
			white6->m_net = net;
			white6->m_msk = mask;
			white6->m_next = 0;
		}
	}
	else
	{
		wl6_t* tmp = white6;

		while ( tmp->m_next != 0 )
			tmp = tmp->m_next;

		tmp->m_next = malloc ( sizeof ( *white6) );

		if ( tmp->m_next != 0 )
		{
			tmp->m_next->m_net = net;
			tmp->m_next->m_msk = mask;
			tmp->m_next->m_next = 0;
		}
	}

	return 0;
}

unsigned char StrIp4ToB ( const char* string, uint32_t* ip )
{
	if ( string != 0 )
	{
		static const char string_tmpl[] = "xxx.xxx.xxx.xxx";
		static const char string_max_len = sizeof ( string_tmpl) / sizeof ( *string_tmpl);

		union IP
		{
			unsigned char ipq[4];
			uint32_t ipb;
		} ipu;

		ipu.ipb = 0;

		char i = 0;
		unsigned char nq = 3;

		while ( *string != 0 && * string != '/' && i < string_max_len )
		{
			if ( *string > 47 && * string < 58 )
				ipu.ipq[nq] = (ipu.ipq[nq] * 10) + (*string - 48);

			if ( *string == '.' || * (string + 1) == 0 || * (string + 1) == '/' )
			{
				if ( nq == 0 )
				{
					*ip = ipu.ipb;
					return i + 1;
				}

				nq --;
			}

			string ++;
			i ++;
		}
	}

	return 0;
}

unsigned char StrIp6ToB ( const char* string, __uint128_t* ip )
{
	if ( string != 0 )
	{
		const char string_tmpl[] = "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx";
		const char string_max_len = sizeof ( string_tmpl) / sizeof ( *string_tmpl);

		unsigned char i = 0;
		unsigned char nq = 7;
		unsigned char ip6un = 0;

		union IP6
		{
			uint16_t ip6q[8];
			__uint128_t ip6b;
		} ip6u;

		ip6u.ip6b = 0;

		while ( string[i] != 0 && string[i] != '/' && i < string_max_len )
		{
			if ( string[i] > 47 && string[i] < 58 )
				ip6u.ip6q[nq] = ip6u.ip6q[nq] << 4 | (string[i] - 48);
			else
			{
				if ( string[i] > 64 && string[i] < 71 )
					ip6u.ip6q[nq] = ip6u.ip6q[nq] << 4 | (string[i] - 55);
				else
				{
					if ( string[i] > 96 && string[i] < 103 )
						ip6u.ip6q[nq] = ip6u.ip6q[nq] << 4 | (string[i] - 87);
				}
			}

			if ( string[i] == ':' || string[i + 1] == 0 || string[i + 1] == '/' )
			{
				nq --;

				if ( string[i] == ':' && string[i + 1] == ':' )
					ip6un = (nq ++);

				if ( string[i + 1] == 0 || string[i + 1] == '/' )
				{
					char e = 0;
					for ( e = nq; e >= 0; e -- )
					{
						unsigned char w = 0;
						for ( w = 0; w < ip6un; w ++ )
						{
							ip6u.ip6q[w] = ip6u.ip6q[w + 1];
							ip6u.ip6q[w + 1] = 0;
						}
					}

					*ip = ip6u.ip6b;

					return i + 1;
				}
			}

			i ++;
		}
	}

	return 0;
}

char StrNet4ToB ( const char* string, uint32_t* ip, uint32_t* mask )
{
	unsigned char l = StrIp4ToB ( string, ip );

	if ( l )
	{
		*mask = 4294967295;

		if ( string[l] == '/' )
		{
			if ( ! StrIp4ToB ( &string[l + 1], mask ) )
			{
				string += l + 1;

				char n = 0;

				while ( *string != 0 )
				{
					if ( *string > 47 && * string < 58 )
						n = (n * 10) + (*string - 48);
					else
						return 1;

					if ( n > 32 )
						return 1;

					string ++;
				}

				*mask = * mask << (32 - n);
			}
		}

		return 1;
	}

	return 0;
}

char StrNet6ToB ( const char* string, __uint128_t* ip, __uint128_t* mask )
{
	unsigned char l = StrIp6ToB ( string, ip );

	if ( l )
	{
		*mask = UINT128_MAX;

		if ( string[l] == '/' )
		{
			string += l + 1;

			char n = 0;

			while ( *string != 0 )
			{
				if ( *string > 47 && * string < 58 )
					n = (n * 10) + (*string - 48);
				else
					return 1;

				if ( n > 128 )
					return 1;

				string ++;
			}

			*mask = * mask << (128 - n);
		}

		return 1;
	}

	return 0;
}
