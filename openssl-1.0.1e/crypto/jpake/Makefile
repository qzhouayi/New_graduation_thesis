top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=jpake sub_all)

all: 
	$(CC) $(INCLUDES) $(CFLAG) -Wall -Werror -g -o mytest mytest.c ../../libcrypto.a

clean:
	rm mytest
