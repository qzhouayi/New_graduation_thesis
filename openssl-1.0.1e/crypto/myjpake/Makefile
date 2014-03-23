top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=myjpake sub_all)

all: 
	$(CC) $(INCLUDES) $(CFLAG) -Wall -Werror -g -o mytest jpaketest.c jpake.c jpake.h ../../libcrypto.a

clean:
	rm mytest
