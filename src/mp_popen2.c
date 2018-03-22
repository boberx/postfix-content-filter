#include "mp_other.h"

pid_t popen2 ( const char* command, int* infp )
{
	int p_stdin[2];
	pid_t pid = -1;

	if ( pipe ( p_stdin ) != 0 )
		return -1;

	pid = fork ();

	if ( pid < 0 )
		return pid;
	else if ( pid == 0 )
	{
		close ( p_stdin[1] );
		dup2 ( p_stdin[0], 0 );

		execl ( "/bin/sh", "sh", "-c", command, NULL );
		perror ( "execl" );
		exit ( 1 );
	}

	if ( infp == 0 )
		close ( p_stdin[1] );
	else
		*infp = p_stdin[1];

	return pid;
}
