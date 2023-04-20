//go:build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

struct digest {
	unsigned char value[32];
};

enum {
	EPERM = 1,
	ENOENT,
};

char __license[] SEC("license") = "Dual BSD/GPL";

extern int bpf_ima_file_appraise(struct file *file) __ksym;
extern struct file *get_task_exe_file(struct task_struct *task) __ksym;
extern void fput(struct file *) __ksym;

SEC("lsm.s/bpf")
int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size) {
	struct task_struct *current = bpf_get_current_task_btf();
	struct file *exe = get_task_exe_file(current);

	if (!exe) {
		__bpf_printk("failed to get exe");
		return 0;
	}

	int ret = bpf_ima_file_appraise(exe);
	fput(exe);

	if (ret == -ENOENT) {
		__bpf_printk("executable not measured by IMA, ignoring");
		return 0;
	}

	if (ret == 0) {
		__bpf_printk("granting access");
		return 0;
	}

	__bpf_printk("denying access: %d", ret);
	return -EPERM;
}
