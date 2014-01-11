top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=zhj_pake sub_all)

all: 
	$(CC) $(INCLUDES) $(CFLAG) -Wall -g -o zhjpake_test zhjpake.c zhjpaketest.c zhjpake.h ../../libcrypto.a

clean:
	rm zhjpake_test
