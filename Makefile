obj-m += simple_module.o
obj-m += sfw_driver.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -o sfw_daemon main.c
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
