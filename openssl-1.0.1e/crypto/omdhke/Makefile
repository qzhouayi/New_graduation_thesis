top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=omdhke sub_all)

all: 
	$(CC) $(INCLUDES) $(CFLAG) -Wall -g -o omdhke_test omdhke.c omdhketest.c omdhke.h ../../libcrypto.a

clean:
	rm omdhke_test
