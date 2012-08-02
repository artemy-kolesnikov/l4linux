MODULES := crypt_driver.o

obj-m := $(MODULES)

ROOTDIR:=../../../src/l4linux

MAKEARCH:=$(MAKE) CROSS_COMPILE=$(CROSS_COMPILE)

all: modules
modules:
	$(MAKEARCH) -C $(ROOTDIR) M=${shell pwd} modules

clean:
	$(MAKEARCH) -C $(ROOTDIR) M=${shell pwd} clean
