#ifndef PS_WHITE_H
#define PS_WHITE_H

#include <syslog.h>
#include <stdlib.h>
#include <netdb.h>

#ifndef UINT128_MAX
#define UINT128_MAX (((__uint128_t)1 << 127) - (__uint128_t)1 + ((__uint128_t)1 << 127))
#endif

typedef struct wl4
{
	uint32_t m_net;
	uint32_t m_msk;
	struct wl4* m_next;
} wl4_t;

extern wl4_t* white4;

typedef struct wl6
{
	__uint128_t m_net;
	__uint128_t m_msk;
	struct wl6* m_next;
} wl6_t;

extern wl6_t* white6;

unsigned char StrIp4ToB ( const char* string, uint32_t* ip );

unsigned char StrIp6ToB ( const char* string, __uint128_t* ip );

char StrNet4ToB ( const char* string, uint32_t* ip, uint32_t* mask );

char StrNet6ToB ( const char* string, __uint128_t* ip, __uint128_t* mask );

char AddWhite4 ( uint32_t net, uint32_t mask );

char AddWhite6 ( __uint128_t net, __uint128_t mask );

#endif
