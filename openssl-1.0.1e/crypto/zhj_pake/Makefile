top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=zhj_pake sub_all)

all: 
	$(CC) $(INCLUDES) $(CFLAG) -Wall -Werror -g -o mytest jpake.c ../../libcrypto.a

clean:
	rm mytest
