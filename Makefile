lo_m_name = low_module
hi_m_name = hi_module
low_dir = "~/low_module/"

obj-m += low_m.o
obj-m += hi_m.o


cache-srcs := cache_structure.o \
			  cache_utilities.o \
			  tcp_flow.o

low_m-objs := $(lo_m_name).o \
			  $(cache-srcs)

hi_m-objs := $(hi_m_name).o \
			 $(cache-srcs)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

netbeans:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/TCP-Flow-Cache modules

clean:
	-rm -f *.o core
	-rm -f *.ko core
	-rm -f *.mod.c core
	-rm -f *.symvers core
	-rm -f *.order core

deploy: all
	mkdir $low_dir 
	cp low_m.ko $low_dir 
