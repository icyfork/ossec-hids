# Makefile for dbd
# Daniel B. Cid <dcid@ossec.net>

PT=../
NAME=ossec-dbd

# Uncomment the following if you know what you are doing.
#DBFLAGS=-I/usr/local/include/mysql -L/usr/local/lib/mysql -lmysqlclient

include ../Config.Make

LOCAL = *.c


# Getting database cflags


OBJS = ${OS_CONFIG} ${OS_SHARED} ${OS_NET} ${OS_REGEX} ${OS_XML}

default:
		@echo "Compiling DB support with: ${DBCHECK}"
		${CC} ${CFLAGS} ${OS_LINK} ${DBFLAGS} ${CDB} ${LOCAL} ${OBJS} -o ${NAME}
clean:
		${CLEAN}
build:
		${BUILD}
