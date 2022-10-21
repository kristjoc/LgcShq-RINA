#
# Written by Francesco Salvestrini <f.salvestrini@nextworks.it>
# Edited by Kr1stj0n C1k0 <kristjoc@uio.no>
#

ifndef KREL
KREL=`uname -r`
endif

ifndef KDIR
KDIR=/lib/modules/$(KREL)/build
endif

ifndef IRATI_KSDIR
IRATI_KSDIR=${PWD}/../../kernel
endif

ccflags-y = -Wtype-limits -I${src}/../../kernel -I${src}/../../include

obj-m := lgcshq-plugin.o
lgcshq-plugin-y := lgcshq-plugin-ps.o rmt-ps-lgcshq.o dtcp-ps-lgcshq.o tcp_lgc_lut.o

all:
	$(MAKE) -C $(KDIR) KBUILD_EXTRA_SYMBOLS=${IRATI_KSDIR}/Module.symvers M=$$PWD modules

clean:
	rm -r -f *.o *.ko *.mod.c *.mod.o Module.symvers .*.cmd .tmp_versions modules.order

install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install
	cp lgcshq-plugin.manifest /lib/modules/$(KREL)/extra/
	depmod -a

uninstall:
	@echo "This target has not been implemented yet"
	@exit 1
