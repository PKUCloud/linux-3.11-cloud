//Author:RSR Date:25/11/13
#ifndef ARCH_X86_KVM_KVM_H
#define ARCH_X86_KVM_KVM_H

#include <asm/vmx.h>
#include <asm/msr.h>
#include <asm/kvm.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <linux/syscalls.h>
#include <linux/kvm_types.h>
#include <linux/kvm.h>
//#include <linux/kvm_host.h>




// we put everything related to kvm in this
// file , right now we only consider VMX

#define KVM_DEBUG_ON 0

#define DBG_NUM_RECS 1000000

/*
#define kvm_debug(...) do{ \
	if(KVM_DEBUG_ON && vcpu->num_recs > DBG_NUM_RECS) printk(KERN_ALERT __VA_ARGS__); \
	} while(0)  

#define KVM_DEBUG_LOG_ON 0 
#define KVM_ERR_ON 1

#define kvm_err(...) do{\
	if(KVM_ERR_ON) printk(KERN_ALERT __VA_ARGS__); \
	} while(0)
*/

#define KVM_RR_NR_MSRS 2

// msr adress

#define KVM_RR_IA32_PMC1  			0xc2
#define KVM_RR_PEFR_ENT_SEL1 			0x187
#define KVM_RR_IA32_PERF_GLOBAL_CTRL		0x38f

// write now we don't worry about overflow 
// in counting guest, we can support 72 hrs of
// recording event if branch occurs every nano second

// WO 
#define KVM_RR_IA32_PERF_GLOBAL_OVF_CTRL 	0x390
#define KVM_RR_IA32_DEBUGCTL			0x1d9
// RO
#define KVM_RR_IA32_PERF_GLOBAL_STATUS 		0x38e

//msr index in save and load area 
#define KVM_RR_PEFR_ENT_SEL1_IDX		0
#define KVM_RR_IA32_PERF_GLOBAL_CTRL_IDX	1
#define KVM_RR_IA32_PMC1_IDX			2
#define KVM_RR_IA32_PERF_GLOBAL_OVF_CTRL_IDX	3
#define KVM_RR_IA32_DEBUGCTL_IDX		4
#define KVM_RR_IA32_PERF_GLOBAL_STATUS_IDX	5



//#define KVM_MAX_LOG_SIZE  (1<<20)
// log format, these are offsets in one log record

#define KVM_RR_LOG_TYPE		0
#define KVM_RR_LOG_DATA_LEN	1	
#define KVM_RR_LOG_TS		3
#define KVM_RR_LOG_DATA		(KVM_RR_LOG_TS + sizeof(struct kvm_rr_ts))


#define KVM_RR_LOG_SIZE(l) 	(KVM_RR_LOG_DATA+l) 

// log record types
#define KVM_RR_RDTSC		1
#define KVM_RR_PIO_IN		2
#define KVM_RR_PIO_OUT		3
#define KVM_RR_MMIO_IN		4
#define KVM_RR_MMIO_OUT		5
#define KVM_RR_EXT_INT		6
#define KVM_RR_HEADER		7
#define KVM_RR_REGS_SET		8
#define KVM_RR_REQ			9


// replay modes of execution

// when waiting for PMI
#define KVM_RPLY_PMI 		1
// when br is near use single step 
#define KVM_RPLY_SS_BR  	2
// debug exception to get right ip 
#define KVM_RPLY_DB_IP  	3
// single step to reach correct ecx
#define KVM_RPLY_SS_ECX 	4
// when no more brach is present but 
// log not exhanusted 
#define KVM_RPLY_SYNC   	5

#define KVM_RPLY_INTR		6

#define KVM_RPLY_BR_THR		32

#define KVM_RPLY_BR_ERR		-100


#define KVM_32_BIT_MAX    	(0xffffffff)

struct kvm_rr_ts
{
	u64 br_count;
	u64 rcx;
	u64 rip;
};

// list of pkts that have to be recorded
struct kvm_rr_reqs_list
{
	gpa_t gpa;
	u32 size;
	u8  req_type;
	struct kvm_rr_reqs_list *next;
};



#define KVM_RR_IRQ_WAIT	  9999

// log data structures


#define KVM_RR_PIO_DATA_MAX 4096
#define KVM_RR_REQ_MAX 4096 // MAX_ETH_FRAME_SIZE doesn't work 



#define NEXT_REC_INTR	1
#define NEXT_REC_REQ	2


struct kvm_rr_req
{

	u8 rec_type;
	char pad[3];
	u32 size;
	gpa_t gpa;
	char data[KVM_RR_REQ_MAX];

};

struct kvm_rr_hdr
{
	u8 rec_type;
	char pad[7];
	struct kvm_rr_ts next_ts;
};


struct kvm_rr_pio_in
{
	// only data is enough for now
	// unsigned long count;
	// int port;
	// int size;
	// current KVM has only data_offset pointing to one page
	// so we use data of one page 
	// when we write this to log we can do better by only
	// writing the whatever data is present rather than writing the
	// whole 4096 data bytes
	u8 rec_type; 
	char data[KVM_RR_PIO_DATA_MAX];
	u64 time_stamp;
}; 

struct kvm_rr_pio_out
{
	u8 rec_type; 
	u64 time_stamp;
	//we do not need to record any data
}; 

struct kvm_rr_regs_set
{
	u8 rec_type;
	char pad[7];
	struct kvm_regs regs;	
};

struct kvm_rr_mmio_in
{
	u8 rec_type; 
	char pad[7];
	gpa_t mmio_phys_addr;
	char data[8];
	u64 time_stamp;
};

struct kvm_rr_mmio_out
{
	u8 rec_type;
	u64 time_stamp;
};

struct kvm_rr_ext_int
{
	u8 rec_type; 
	u8 int_vec;
	//u8 is_realmode;
	u8 irq;
	u32 irq_count;
	struct kvm_rr_ts next_ts;
};

struct kvm_rr_rdtsc
{
	u8 rec_type;
	char pad[7];
	u64 tsc;
};
 

#define header_next_ts_offset() \
	(KVM_RR_LOG_TS)

#define ext_int_next_ts_offset() \
	(KVM_RR_LOG_DATA + offsetof(struct kvm_rr_ext_int, next_ts))

#define pio_data_offset() \
	(KVM_RR_LOG_DATA - sizeof(struct kvm_rr_ts))

#define mmio_data_offset() \
	(KVM_RR_LOG_DATA - sizeof(struct kvm_rr_ts))


 
static const u32 rr_msr_map[] =
{
	KVM_RR_PEFR_ENT_SEL1,
	KVM_RR_IA32_PERF_GLOBAL_CTRL,
	KVM_RR_IA32_PMC1,
	KVM_RR_IA32_PERF_GLOBAL_OVF_CTRL,
	KVM_RR_IA32_DEBUGCTL,
	KVM_RR_IA32_PERF_GLOBAL_STATUS,
};



struct msr_autosave_rr 
{
	int is_counting;
	struct vmx_msr_entry exit_store_guest[KVM_RR_NR_MSRS];
	struct vmx_msr_entry exit_load_host[KVM_RR_NR_MSRS];

	// following structure should filled up using previously saved
	// values in exit_store_guest 
	struct vmx_msr_entry entry_load_guest[KVM_RR_NR_MSRS];

	// when we enter into guest we make sure we will save
	// host registers into exit_load_host so that upon exit
	// CPU will automatically restore this.
	// before this saving and VMENTRY we will make sure that
	// we disable the preempt to avoid resuming on the different
	// CPU after this store.
	

} ;



#define vcpu_disable_rply(vcpu) \
	kvm_err("Disabling rply bc %lld ip %x cx %x %lld\n",vcpu->stop_at_ts.br_count,\
			vcpu->stop_at_ts.rip,vcpu->stop_at_ts.rcx,\
			vcpu->num_recs);\
	vcpu->is_replaying = 0; \
	vcpu->run->is_replaying = 0; 



struct kvm_vcpu;


char * print_u64_raw(void * raw);

int is_kvm_rr_msr(u32 msr);

u64 read_pmc1(void);

void init_kvm_rr_msr(struct msr_autosave_rr *msr_rr);

int config_msr_rr_state(struct msr_autosave_rr *msr_rr);

void save_host_msr_rr_state(struct msr_autosave_rr *msr_rr);

void copy_guest_store_to_load(struct msr_autosave_rr *msr_rr);

void inline clear_ovf_bit_pmc1(void);

int inline check_ovf_bit_pmc1(void);

int kvm_rr_rec_reqs(struct kvm_vcpu *vcpu);

int kvm_rr_req_handle(struct kvm_vcpu *vcpu, struct kvm_rr_reqs_list *pkt);

int write_log(u8 log_type, struct kvm_vcpu *vcpu, u16 data_len,
				void *data);
//char * get_log_buf();

//void *get_log_data_ptr(struct kvm_vcpu *vcpu);

u8  read_log(struct kvm_vcpu *vcpu);

int kvm_log_file_open(char *file_name);

int kvm_log_file_write(int fd, const char *buf, size_t count);

int kvm_log_file_read(int fd, const char *buf, size_t count);

int kvm_log_file_sync(int fs);

#endif

