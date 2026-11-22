# Out-of-tree module for the lab kernel (built with module BTF, which is
# needed to attach fentry/fmod_ret to its functions).
KDIR ?= $(HOME)/kernels/linux-7.3.1
obj-m := privsim.o

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
