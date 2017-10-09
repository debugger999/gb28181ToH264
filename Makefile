CC = g++
CFLAGS = -Wall -O2 -Iwork/include -Iwork/cjson -Iwork/sip/include
CFLAGS += -Iwork/mxml-2.10/include -Iwork/MD5
LDFLAGS = -Lwork/sip/lib
LDFLAGS += -leXosip -losip2 -lmd5 -lmxml -lpthread -lrt
SRC = main.cpp work/cjson/cJSON.c

all:
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -o gb28181ToH264

clean:
	rm -f *.o gb28181ToH264

