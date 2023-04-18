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
};

char __license[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct digest);
	__type(value, u32);
	__uint(max_entries, 0);
} allowed SEC(".maps");

SEC("lsm.s/bpf")
int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size) {
	struct task_struct *task = bpf_get_current_task_btf();
	struct file *exe = task->mm->exe_file;
	struct inode *inode = exe->f_inode;

	if (!bpf_core_field_exists(inode->i_verity_info)) {
		__bpf_printk("CONFIG_FS_VERITY disabled");
		return 0;
	}

	struct fsverity_info *verity = inode->i_verity_info;
	if (!verity) {
		__bpf_printk("no verity information");
		return -EPERM;
	}

	struct digest digest;
	__builtin_memcpy((void*)digest.value, verity->file_digest, sizeof(digest.value));

	void *found = bpf_map_lookup_elem(&allowed, digest.value);
	if (found) {
		__bpf_printk("granting access");
		return 0;
	}

	__bpf_printk("denying access");
	return -EPERM;
}
