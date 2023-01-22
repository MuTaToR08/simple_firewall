obj-m += sfw_module.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -pthread -o sfw_daemon main.c
install:
	if [ ! -d /lib/modules/$(shell uname -r)/extra ]; then mkdir /lib/modules/$(shell uname -r)/extra; fi;
	cp sfw_module.ko /lib/modules/$(shell uname -r)/extra/sfw_module.ko
profiler:
	gcc -Wall -fno-inline -pg -pthread -o sfw_daemon main.c
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm sfw_daemon
