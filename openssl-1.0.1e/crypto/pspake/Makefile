top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=pspake sub_all)

all: 
	$(CC) $(INCLUDES) $(CFLAG) -Wall -g -o pspake_test pspake.c pspaketest.c pspake.h ../../libcrypto.a

clean:
	rm pspake_test
