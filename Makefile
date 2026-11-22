# CredNotary: BPF programs (clang -target bpf, CO-RE) and a user-space loader
# linked statically against libbpf, so that the binaries run in the busybox
# initramfs of the lab VM without dependencies.
#
#   make deps          libbpf and bpftool from the kernel tree (KSRC), once
#   make               loader, compat variants, privsim, test helpers, benchmark
#   make crednotary    loader only (build/crednotary)
#
# KSRC is a configured and built kernel tree (default: ~/kernels/linux-7.3.1).
KSRC     ?= $(HOME)/kernels/linux-7.3.1
BUILD    := $(CURDIR)/build
BPFTOOL  := $(BUILD)/bpftool/bpftool
LIBBPF   := $(BUILD)/libbpf
CLANG    ?= clang

BPF_CFLAGS := -O2 -g -Wall -Wno-unused-function -Wno-missing-declarations -target bpf -D__TARGET_ARCH_x86 \
	      -I$(CURDIR)/include -I$(LIBBPF)/include
CFLAGS     := -O2 -g -Wall -I$(LIBBPF)/include
LDLIBS     := -static $(LIBBPF)/lib64/libbpf.a -lelf -lz -lzstd

all: crednotary crednotary-compat testmod helpers bench

deps:
	scripts/build-deps.sh "$(KSRC)" "$(BUILD)"

$(BUILD)/obj:
	mkdir -p $@

# Main build: kernels >= 6.13 (also loads on older ones, see README)
$(BUILD)/obj/crednotary.bpf.o: src/crednotary.bpf.c src/crednotary.h include/vmlinux.h | $(BUILD)/obj
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/obj/crednotary.skel.h: $(BUILD)/obj/crednotary.bpf.o
	$(BPFTOOL) gen skeleton $< name crednotary_bpf > $@

$(BUILD)/crednotary: src/crednotary.c src/crednotary.h $(BUILD)/obj/crednotary.skel.h
	$(CC) $(CFLAGS) -I$(BUILD)/obj $< -o $@ $(LDLIBS)

crednotary: $(BUILD)/crednotary

# Compatibility variants from the same source and loader: compat (5.13-6.12,
# task storage) and compat-hash (5.11-5.12, hash map). Skeletons in
# build/obj/<variant>.
CN_VARIANTS := compat compat-hash
CN_DEFS_compat      := -DPG_COMPAT
CN_DEFS_compat-hash := -DPG_COMPAT -DPG_SHADOW_HASH

define CN_RULES
$(BUILD)/obj/$(1)/crednotary.bpf.o: src/crednotary.bpf.c src/crednotary.h include/vmlinux.h
	mkdir -p $$(@D)
	$$(CLANG) $$(BPF_CFLAGS) $(CN_DEFS_$(1)) -c $$< -o $$@

$(BUILD)/obj/$(1)/crednotary.skel.h: $(BUILD)/obj/$(1)/crednotary.bpf.o
	$$(BPFTOOL) gen skeleton $$< name crednotary_bpf > $$@

$(BUILD)/crednotary-$(1): src/crednotary.c src/crednotary.h $(BUILD)/obj/$(1)/crednotary.skel.h
	$$(CC) $$(CFLAGS) -I$$(BUILD)/obj/$(1) $$< -o $$@ $$(LDLIBS)
endef
$(foreach v,$(CN_VARIANTS),$(eval $(call CN_RULES,$(v))))

crednotary-compat: $(addprefix $(BUILD)/crednotary-,$(CN_VARIANTS))

# Lab module, for KSRC (the kernel the VM boots)
testmod:
	$(MAKE) -C testmod KDIR=$(KSRC)

# privsim for an older kernel tree, in build/oldk/privsim-<version>/ (used by
# tests/crednotary-oldk.sh):   make oldk-privsim OLDK=~/kernels/old/linux-5.15
OLDK_VER = $(shell $(MAKE) -s -C $(OLDK) kernelversion)
oldk-privsim:
	@[ -n "$(OLDK)" ] || { echo "usage: make oldk-privsim OLDK=<kernel tree>"; exit 1; }
	mkdir -p $(BUILD)/oldk/privsim-$(OLDK_VER)
	cp testmod/privsim.c testmod/privsim.h testmod/Makefile $(BUILD)/oldk/privsim-$(OLDK_VER)/
	$(MAKE) -C $(OLDK) M=$(BUILD)/oldk/privsim-$(OLDK_VER) \
		$(if $(filter 5.%,$(OLDK_VER)),PAHOLE=$(CURDIR)/vm/pahole-compat.py) modules

helpers: $(BUILD)/runas $(BUILD)/privsim-test $(BUILD)/suid-check $(BUILD)/setfcap

$(BUILD)/suid-check: tests/helpers/suid-check.c | $(BUILD)/obj
	$(CC) -static -O2 -Wall $< -o $@

$(BUILD)/setfcap: tests/helpers/setfcap.c | $(BUILD)/obj
	$(CC) -static -O2 -Wall $< -o $@

$(BUILD)/runas: tests/helpers/runas.c | $(BUILD)/obj
	$(CC) -static -O2 -Wall $< -o $@

$(BUILD)/privsim-test: tests/helpers/privsim-test.c testmod/privsim.h | $(BUILD)/obj
	$(CC) -static -O2 -Wall -Itestmod $< -o $@

bench: $(BUILD)/pgbench

$(BUILD)/pgbench: bench/pgbench.c | $(BUILD)/obj
	$(CC) -static -O2 -Wall $< -o $@

clean:
	rm -rf $(BUILD)/obj $(BUILD)/crednotary $(addprefix $(BUILD)/crednotary-,$(CN_VARIANTS)) \
		$(BUILD)/runas $(BUILD)/privsim-test $(BUILD)/suid-check $(BUILD)/setfcap $(BUILD)/pgbench
	$(MAKE) -C testmod KDIR=$(KSRC) clean

.PHONY: all deps crednotary crednotary-compat testmod oldk-privsim helpers bench clean
.SECONDARY:
