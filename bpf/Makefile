CC ?= gcc
LLC ?= llc
CLANG ?= clang

EXTRA_CFLAGS ?= -g -O2 -emit-llvm
# INC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`
INC_FLAGS ?=

SRC := $(wildcard *.c)
OBJS := $(SRC:%.c=%.o)

all: $(OBJS)

%.o: %.c
	$(CLANG) $(INC_FLAGS) \
		-D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option \
		$(EXTRA_CFLAGS) -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@

.PHONY: clean
clean:
	rm -f $(OBJS)

