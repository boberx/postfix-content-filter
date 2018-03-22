CC=gcc
CFLAGS=-Wall
BINDIR=./bin
BINNAME=mailparser

main: dir mp_popen2 mp_getopt mp_white mp_white_test
	$(CC) ${CFLAGS} -o ${BINDIR}/${BINNAME} \
		mp_main.c \
		${BINDIR}/mp_popen2.o \
		${BINDIR}/mp_getopt.o \
		${BINDIR}/mp_white_test.o \
		${BINDIR}/mp_white.o \
		-lrt

mp_popen2: dir
	$(CC) ${CFLAGS} -c -o ${BINDIR}/mp_popen2.o mp_popen2.c

mp_getopt: dir
	$(CC) $(CFLAGS) -c -o ${BINDIR}/mp_getopt.o mp_getopt.c

mp_white: dir
	$(CC) $(CFLAGS) -c -o ${BINDIR}/mp_white.o mp_white.c

mp_white_test: dir
	$(CC) $(CFLAGS) $(INCLUDE) -c -o ${BINDIR}/mp_white_test.o mp_white_test.c

dir:
	mkdir -p ${BINDIR}

clean:
	rm -rf ${BINDIR}
