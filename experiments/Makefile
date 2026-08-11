# Makefile for RQ2 experiment probe programs
#
# Each probe is a standalone C program that executes exactly one side-effecting
# syscall and reports the result. Compiled statically where possible to avoid
# library path issues inside mount namespaces.

CC       := gcc
CFLAGS   := -Wall -Wextra -O2 -g -I.
LDFLAGS  := -static
BINDIR   := bin

# Probes that need extra libraries
IO_URING_LIBS := -luring
MQ_LIBS       := -lrt -lpthread
KEYUTILS_LIBS := -lkeyutils

# All probe sources
FS_PROBES := fs_write fs_create fs_delete fs_rename fs_link fs_symlink \
             fs_truncate fs_chmod fs_chown fs_mkdir fs_rmdir fs_read fs_mknod

NET_PROBES := net_connect net_bind net_send

IPC_PROBES := ipc_pipe ipc_unix ipc_shm ipc_msg ipc_sem ipc_mq ipc_mmap

SIG_PROBES := sig_kill sig_ptrace

PRIV_PROBES := priv_setuid priv_setgid priv_setgroups priv_capset priv_exec

OUT_PROBES := out_write out_sendfile out_splice out_io_uring

SYS_PROBES := sys_mount sys_unshare sys_setns sys_keyctl sys_bpf \
              sys_perf sys_tty_ioctl sys_process_vm sys_umount sys_add_key \
              sys_process_vm_writev

ALL_PROBES := $(FS_PROBES) $(NET_PROBES) $(IPC_PROBES) $(SIG_PROBES) \
              $(PRIV_PROBES) $(OUT_PROBES) $(SYS_PROBES)

# Default: build all probes (try static, fall back to dynamic)
.PHONY: all clean

all: $(BINDIR)
	@for probe in $(ALL_PROBES); do \
		if [ "$$probe" = "out_io_uring" ]; then \
			$(CC) $(CFLAGS) -o $(BINDIR)/$$probe $$probe.c $(IO_URING_LIBS) 2>/dev/null || \
			$(CC) $(CFLAGS) -o $(BINDIR)/$$probe $$probe.c $(IO_URING_LIBS) $(LDFLAGS) 2>/dev/null || \
			echo "SKIP $$probe (liburing not available)"; \
		elif [ "$$probe" = "ipc_mq" ]; then \
			$(CC) $(CFLAGS) -o $(BINDIR)/$$probe $$probe.c $(MQ_LIBS) 2>/dev/null || \
			$(CC) $(CFLAGS) $(LDFLAGS) -o $(BINDIR)/$$probe $$probe.c $(MQ_LIBS) 2>/dev/null || \
			echo "SKIP $$probe (librt not available)"; \
		elif [ "$$probe" = "sys_add_key" ]; then \
			$(CC) $(CFLAGS) -o $(BINDIR)/$$probe $$probe.c $(KEYUTILS_LIBS) 2>/dev/null || \
			$(CC) $(CFLAGS) $(LDFLAGS) -o $(BINDIR)/$$probe $$probe.c $(KEYUTILS_LIBS) 2>/dev/null || \
			echo "SKIP $$probe (libkeyutils not available)"; \
		else \
			$(CC) $(CFLAGS) $(LDFLAGS) -o $(BINDIR)/$$probe $$probe.c 2>/dev/null || \
			$(CC) $(CFLAGS) -o $(BINDIR)/$$probe $$probe.c || \
			echo "FAIL $$probe"; \
		fi; \
	done
	@echo "Build complete. Binaries in $(BINDIR)/"

$(BINDIR):
	mkdir -p $(BINDIR)

# Individual probe targets for development
$(FS_PROBES): %: $(BINDIR) %.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BINDIR)/$@ $@.c

$(NET_PROBES): %: $(BINDIR) %.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BINDIR)/$@ $@.c

$(IPC_PROBES): %: $(BINDIR) %.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BINDIR)/$@ $@.c

ipc_mq: $(BINDIR) ipc_mq.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BINDIR)/$@ $< $(MQ_LIBS)

$(SIG_PROBES): %: $(BINDIR) %.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BINDIR)/$@ $@.c

$(PRIV_PROBES): %: $(BINDIR) %.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BINDIR)/$@ $@.c

$(OUT_PROBES): %: $(BINDIR) %.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BINDIR)/$@ $@.c

out_io_uring: $(BINDIR) out_io_uring.c common.h
	$(CC) $(CFLAGS) -o $(BINDIR)/$@ $< $(IO_URING_LIBS)

$(SYS_PROBES): %: $(BINDIR) %.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BINDIR)/$@ $@.c

clean:
	rm -rf $(BINDIR)

# List all probes
list:
	@echo $(ALL_PROBES) | tr ' ' '\n'
