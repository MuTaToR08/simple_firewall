obj-m += simple_module.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -pthread -o sfw_daemon main.c
profiler:
	gcc -Wall -fno-inline -pg -pthread -o sfw_daemon main.c
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
