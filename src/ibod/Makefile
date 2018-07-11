CC=gcc
CFLAGS=
EXEC_NAME=ibod
INSTALL_DIR=/usr/sbin
CONFIG_FILE=ibod.cf
CONFIG_DIR=/etc/ppp

default : ibod

clean : 
	rm -f ${EXEC_NAME}

ibod : ibod.c
	${CC} ${CFLAGS} -o ${EXEC_NAME} ibod.c

install : 
	install -d -m 0755 ${INSTALL_DIR} ${CONFIG_DIR}
	install -m 0755 ${EXEC_NAME} ${INSTALL_DIR}
	install -m 0644 ${CONFIG_FILE} ${CONFIG_DIR}
