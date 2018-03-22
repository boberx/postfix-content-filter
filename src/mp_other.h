#ifndef MP_OTHER_H
#define MP_OTHER_H

#define MP_VERSION				"1.3.5"
#define MP_AUTHOR				"Bober"

#define MP_DEBUG				0

#define MP_LG_TTL				"postfix/mailparser"

#define MP_MAX_MSG_SIZE			62914560
#define MP_MAX_CMD_LEN			26000

#define MP_MAX_EMAIL_STR		254

#define MP_MAX_RCPT				100
#define MP_MAX_RCPT_NOTDOS		10
#define MP_MAX_RCPT_STR			(MP_MAX_RCPT * MP_MAX_EMAIL_STR) + MP_MAX_RCPT + (MP_MAX_RCPT_NOTDOS * 3)

#define MP_AV_TTL				"clamav"
#define MP_AV_CMD				"/usr/bin/clamdscan - --quie"
#define MP_AV_STREAM_MAX_LEN	10485760

#define MP_SM_CMD				"/usr/sbin/sendmail -oi -f %s %s"

#define MP_SA_MAX_MSG_SIZE		524288
#define MP_SA_CMD				"/usr/bin/spamc -u %s -s 1048576 -e /usr/sbin/sendmail -oi -f %s %s"
#define MP_SA_GLOBAL_USER		"GLOBAL"

#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <sysexits.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>

#include "mp_getopt.h"
#include "mp_white_test.h"

extern pid_t popen2 ( const char* command, int* infp );


//getconf ARG_MAX
//2097152
//25430

#endif
