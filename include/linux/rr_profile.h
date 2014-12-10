#ifndef __RR_PROFILE_H
#define __RR_PROFILE_H


#define RR_PROFILE

struct vmexit_states {
	uint64_t num;
	uint64_t time;
};

struct vcpu_rr_states {
	uint64_t vm_time, kvm_time;
	uint64_t total_commit_time, page_commit_time;
	uint64_t walk_mmu_time, set_dirty_bit_time, detect_conflict_time;
	struct vmexit_states vmexit_states[60];
	int exit_reason;
};

static inline uint64_t rr_rdtsc(void)
{
	unsigned int low, high;

	asm volatile("rdtsc" : "=a" (low), "=d" (high));

	return low | ((unsigned long long)high) << 32;
}

#endif