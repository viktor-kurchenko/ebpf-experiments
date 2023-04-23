TARGET = udp
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_OBJ = ${TARGET:=.bpf.o}

all: $(TARGET) $(BPF_OBJ)
.PHONY: all
.PHONY: $(TARGET)

$(TARGET): $(BPF_OBJ)
	tc qdisc add dev lo clsact
	tc filter add dev lo ingress bpf object-file $(BPF_OBJ) section tc direct-action

$(BPF_OBJ): %.o: %.c vmlinux.h
	clang \
	    -target bpf \
	    -D __BPF_TRACING__ \
		-I/usr/include/$(shell uname -m)-linux-gnu \
	    -Wall \
	    -O2 -o $@ -c $<

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	- tc qdisc del dev lo clsact
	- rm $(BPF_OBJ)
