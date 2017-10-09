# -MM
# -pipe : Use pipes rather than temporary files for communication between the various stages of compilation.


CROSS_COMPILE=
CC = $(CROSS_COMPILE)gcc 

CFLAG += -Wall -W -g -Os -o

AR = $(CROSS_COMPILE)ar crv 
RANLIB = $(CROSS_COMPILE)ranlib -t 
STRIP = $(CROSS_COMPILE)strip


OBJ := MD5.o 
OBJ += HTTPDigest.o 
OBJ += test.o

TARGET = libmd5.a

all: $(OBJ)
	#$(CC) -shared $(CFLAG) $(TARGET) $(OBJ) $(LIBS)
	$(AR) $(TARGET) $(OBJ)
	$(RANLIB) $(TARGET)
	chmod 777 $(TARGET)

$(OBJ): %.o:%.c
	$(CC) -c  $< $(CFLAG) $@ $(INCLUDE)

clean:
	rm -rf $(OBJ) 

