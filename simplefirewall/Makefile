obj-m += simplefirewall.o
all:	
	make --debug=j -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:	
	make --debug=j -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
