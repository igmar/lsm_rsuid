KERNEL_SRC=/lib/modules/`uname -r`/build
KERNEL_MOD=/lib/modules/`uname -r`

obj-m = lsm_rsuid.o

build: test-rsuid
	make -C $(KERNEL_SRC) SUBDIRS=`pwd` modules

install:
	cp -f lsm_rsuid.ko $(KERNEL_MOD)/kernel/security

test-rsuid: test-rsuid.c
	$(CC) -o $@ $^

clean:
	rm -rf *.o .*.d *.ko *.mod.o *.mod.c .*.cmd .tmp_versions test-rsuid

distclean: clean

