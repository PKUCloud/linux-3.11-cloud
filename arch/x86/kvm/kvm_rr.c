// Author:RSR Date:25/11/13

#include <asm/vmx.h>
#include <asm/msr.h>
#include <asm/kvm_rr.h>
#include <linux/fcntl.h>
#include <linux/kvm_host.h>
#include <linux/kvm.h>
// kvm rsr
#include <linux/kernel.h>
//end kvm rsr




// global buffer that will be used by recording VCPU
// to formulate log record
//
// right now we only target non SMP so safe to go with lock


//char log_buf[KVM_MAX_LOG_SIZE];



int is_kvm_rr_msr(u32 msr)
{
	// just be cautious even for global ctrl and status

	switch(msr)
	{
		case KVM_RR_IA32_PMC1:
		case KVM_RR_PEFR_ENT_SEL1:
		case KVM_RR_IA32_PERF_GLOBAL_STATUS:
		case KVM_RR_IA32_PERF_GLOBAL_CTRL:
		case KVM_RR_IA32_PERF_GLOBAL_OVF_CTRL:
		case KVM_RR_IA32_DEBUGCTL: 
			return 1;
		default:
			return 0;

	}

	return 0;
}


void init_kvm_rr_msr(struct msr_autosave_rr *msr_rr)
{
	
	int i;
	// setup exit guest store area
	for( i=0; i<KVM_RR_NR_MSRS; i++)
	{
		msr_rr->exit_store_guest[i].index = rr_msr_map[i];
		msr_rr->exit_store_guest[i].reserved = 0;
		msr_rr->exit_store_guest[i].value = 0;
	}
	
	// setup exit host load area
	for( i=0; i<KVM_RR_NR_MSRS; i++)
	{
		msr_rr->exit_load_host[i].index = rr_msr_map[i];
		msr_rr->exit_load_host[i].reserved = 0;
		msr_rr->exit_load_host[i].value = 0;
	}

	// setup entry guest load area
	for( i=0; i<KVM_RR_NR_MSRS; i++)
        {
                msr_rr->entry_load_guest[i].index = rr_msr_map[i];
                msr_rr->entry_load_guest[i].reserved = 0;
                msr_rr->entry_load_guest[i].value = 0;
        }

	
}
EXPORT_SYMBOL_GPL(init_kvm_rr_msr);


// this enable/config the PMC's for counting during VM recoding
// this will be called before first vm entry after enabling 
// recording and before copy_guest_store_to_load()
int config_msr_rr_state(struct msr_autosave_rr *msr_rr)
{

	msr_rr->is_counting = 1;
	//msr_rr->exit_store_guest[KVM_RR_IA32_PMC1_IDX].value = 0x0;
	// branch instruction retired
	msr_rr->exit_store_guest[KVM_RR_PEFR_ENT_SEL1_IDX].value = 0x5304c4;
	//See Intel  Developer's Manual Vol. 3B 18-3 
	//Event select field (bits 0 through 7) : C4 --  Branch Instruction Retired
	//04--support precise-event-based sampling (PEBS)
	//USR (user mode) flag (bit 16)
	//OS (operating system mode) flag (bit 17)
	//INT (APIC interrupt enable) flag (bit 20)
	//EN (Enable Counters) Flag (bit 22)

	// we need to enable only PMC1
	msr_rr->exit_store_guest[KVM_RR_IA32_PERF_GLOBAL_CTRL_IDX].value = 0x2;
	//See Intel  Developer's Manual 18-6 Vol. 3B
	//IA32_PMC1 enable

	
	
	// KVM_RR_IA32_PERF_GLOBAL_STATUS is RO so nothing to do
	// we hope we won't face any overflow during recording 
	// phase (HAVE TO REMOVE THIS ASSUMPTION LATER)
	
	// so no change for KVM_RR_IA32_PERF_GLOBAL_OVF_CTRL
	
	// no change in KVM_RR_IA32_DEBUGCTL for now 
	//
	return 0;

}
EXPORT_SYMBOL_GPL(config_msr_rr_state);


void inline clear_ovf_bit_pmc1()
{
	wrmsrl(KVM_RR_IA32_PERF_GLOBAL_OVF_CTRL, 0x2);
}
EXPORT_SYMBOL_GPL(clear_ovf_bit_pmc1);


int inline check_ovf_bit_pmc1()
{

	u64 val;
	rdmsrl(KVM_RR_IA32_PERF_GLOBAL_STATUS, val);
	return val & 0x2;
}


u64 read_pmc1()
{
	unsigned eax =0x0;
	unsigned edx =0x0;
	unsigned msr_addr = KVM_RR_IA32_PMC1 ; //0x38f;
	unsigned long long result;

	__asm__ __volatile__ ("mov %2, %%ecx\n\t"
		"rdmsr\n\t"
		"mov %%eax, %0\n\t"
		"mov %%edx, %1\n\t"
		: "=&r" (eax), "=&r" (edx)
		: "r"(msr_addr)
		: "eax", "ecx", "edx"); /* eax, ecx, edx clobbered */

	result = ((unsigned long long)edx << 32) | eax;
	return result;
}
EXPORT_SYMBOL_GPL(read_pmc1);

// this will save the require host msr state 
// into VMCS specified mem area, these values will be
// restored upon vm exit.
// SHOULD BE CALLED BEFORE VM ENTRY
void save_host_msr_rr_state(struct msr_autosave_rr *msr_rr)
{

	int i;
	for(i=0; i<KVM_RR_NR_MSRS; i++)
	{
		//kvm_debug(" msr addr %x val %llx \n",rr_msr_map[i],
		//		msr_rr->exit_load_host[i].value);
		rdmsrl(rr_msr_map[i],msr_rr->exit_load_host[i].value);	
	}

}
EXPORT_SYMBOL_GPL(save_host_msr_rr_state);



// this will save the stored guest msrs into VMCS area which
// will be used to load when vm entry happens
// SHOULD BE CALLED BEFORE VM ENTRY
void copy_guest_store_to_load(struct msr_autosave_rr *msr_rr)
{
	memcpy(&msr_rr->entry_load_guest,&msr_rr->exit_store_guest,\
			sizeof(msr_rr->exit_store_guest));		
			
}
EXPORT_SYMBOL_GPL(copy_guest_store_to_load);

int kvm_rr_req_handle(struct kvm_vcpu *vcpu, struct kvm_rr_reqs_list *req)
{
	gfn_t gfn;
	int offset;
	unsigned long hva;
	unsigned int *rfd_sts;

	if(kvm_record) {
		struct kvm_rr_req *req_log = (struct kvm_rr_req *)kmalloc(sizeof(struct kvm_rr_req), GFP_KERNEL);
		
		if(req->size > KVM_RR_REQ_MAX) {
			// should not occur
			kvm_err("big req than buffer size %d\n",req->size);
			return 0;
		}
	
		// copy from rfd to log
		/*
		if(vcpu->log_offset == -1 && vcpu->is_recording) {
			struct kvm_rr_hdr hdr_log;
			hdr_log.next_rec_type = 0;
			// recording just started , write file header first
			write_log(KVM_RR_HEADER, vcpu, sizeof(struct kvm_rr_hdr), &hdr_log);
		}
		*/

		req_log->rec_type = KVM_RR_REQ;
		req_log->gpa = req->gpa;
		req_log->size = req->size;

		gfn = req->gpa >> PAGE_SHIFT;
		hva = gfn_to_hva(vcpu->kvm, gfn);
		offset = offset_in_page(req->gpa);

		if(req->req_type == REC_TYPE_RX_PKT) {
			rfd_sts = (unsigned int *)(hva+offset);
			*rfd_sts = (*rfd_sts | (1<<15));
			kvm_debug("rfd_sts %x\n",*rfd_sts);
		}

		memcpy(req_log->data, (void *)(hva+offset), req_log->size);
			
		write_log(KVM_RR_REQ, vcpu, (sizeof(struct kvm_rr_req) - (KVM_RR_REQ_MAX - req->size)), (void *)req_log);
		kfree(req_log);
		//reset counter to zero .. next event is relative 
		// from here
		vcpu->rr_ts.br_count = 0;
			
	} // end of recording

	/*
	else if(vcpu->is_replaying) {
		struct kvm_rr_req *req_log = NULL;
		int ret;
		ret = read_log(vcpu);	
		if(ret <= 0 || ret != KVM_RR_REQ) {
			// disable replaying , undefined behavior
			kvm_err("is out of sync %d expecting KVM_RR_REQ,\
					 got %d\n", ret != KVM_RR_REQ, ret);
			vcpu_disable_rply(vcpu);
              	}
		else {
			// just copy the input data from log file
			req_log = get_log_data_ptr(vcpu);
		}
		if(!req_log) {
			// disable replaying , undefined behavior
			kvm_err("couldn't get data ptr\n");
			vcpu_disable_rply(vcpu);
		}
		else {
			
			vcpu->next_rec_type = req_log->next_rec_type;
			// copy to the place where user space would have
			// copied 
			gfn = req_log->gpa >> PAGE_SHIFT;
			hva = gfn_to_hva(vcpu->kvm, gfn);
			offset = offset_in_page(req_log->gpa);
	
			memcpy(hva+offset, req_log->data, req_log->size);
			kvm_debug_log("RPLY_REQ %lu:%llu,%llx,%llx:size %d addr %x %d\n",\
	               vcpu->num_recs,vcpu->rr_ts.br_count,vcpu->rr_ts.rcx,vcpu->rr_ts.rip,req_log->size,\
				 req_log->gpa,sizeof(struct kvm_rr_req));
	
			vcpu->rr_ts.br_count = 0;
		
		}

	}// end of replay	
	*/
	return 0;
}

// this function will write the pending pkts to log file
// and set the COMPLETE_BIT on rfd. And also free the pending pkts
// data structure
int kvm_rr_rec_reqs(struct kvm_vcpu *vcpu)
{
		
	struct kvm_rr_reqs_list *list=NULL,*temp;

	
	if(!kvm_record) {
		// we should have empty list
		if(vcpu->pending_reqs)
			kvm_err("Not recording but list is non-empty\n");
		
		return 0;
	}


	// take the pending pkts lock and store
	// that list in a local variable, so lock can be 
	// release for further pkts addition, which guest see
	// in the next iteration.
	spin_lock(&vcpu->pending_reqs_lock);
	
	list = (struct kvm_rr_reqs_list *)(vcpu->pending_reqs);
	vcpu->pending_reqs = NULL;
	
	spin_unlock(&vcpu->pending_reqs_lock);
	
	while(list) {
		
		kvm_rr_req_handle(vcpu, list);
		temp = list;
		list = temp->next;
		kvm_debug("removing reqs from peding list %llx\n", (u64)temp);
		kfree(temp);

	}	
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_rr_rec_reqs);


/*
int kvm_rr_rply_reqs(struct kvm_vcpu *vcpu)
{	
	while(vcpu->next_rec_type == NEXT_REC_REQ)
	{
		kvm_rr_req_handle(vcpu,NULL);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_rr_rply_reqs);
*/


// this will return the pointer to payload in the
// current log record. Caller should make sure 
// proper log record is being pointed by log_offset
// in vcpu struct
/*
void *get_log_data_ptr(struct kvm_vcpu *vcpu)
{

	u8 log_type; 
	struct kvm_run *run = vcpu->run;
	char *buf = run->ring_buffers[run->ring_buf_kvm_ptr];

	log_type = (buf+vcpu->log_offset)[0];

	switch(log_type)
	{
		case KVM_RR_PIO_IN:
		case KVM_RR_RDTSC:
		case KVM_RR_MMIO_IN:
		case KVM_RR_HEADER:
		case KVM_RR_REGS_SET:
		case KVM_RR_REQ:
			// account only type and length
			return (void *)(buf+vcpu->log_offset+3);
		case KVM_RR_EXT_INT:
			return (void *)(buf+vcpu->log_offset+\
						3+sizeof(struct kvm_rr_ts));
		default:
			kvm_err("Invalid log type %u\n",log_type);
	}
	return NULL;	
}
EXPORT_SYMBOL_GPL(get_log_data_ptr);
*/


// reads record by record and sets the offset in log_buf in
// vcpu->log_offset. 
// returns log type 
// returns 0 if incomplete block is found / log file is exhausted
// and considered to be the end of replaying
// returns -1 if any error

// log_rec_len will be used to store the record len.
/*
u8  read_log(struct kvm_vcpu *vcpu)
{

	int ret;
	struct kvm_run *run = vcpu->run;
	u16 *data_len;
	u8 log_type;
	char *buf = run->ring_buffers[run->ring_buf_kvm_ptr];


	if(vcpu->log_offset == -1)
	{
		vcpu->log_offset = 0;		
		vcpu->log_rec_len = 0;
	}

	// advance the offset to the end of prev log rec
	vcpu->log_offset += vcpu->log_rec_len;

	// skip fill chars till the block is done
	if( (buf+vcpu->log_offset)[0] == 0\
			 || vcpu->log_offset >= KVM_MAX_LOG_SIZE)
	{
		// either filler block is found or block is completed
		// read new block
		run->invalid_exit_reason = 1;
		run->ring_buf_kvm_ptr = (run->ring_buf_kvm_ptr + 1)% KVM_RR_RING_BUF_SIZE; 
		buf = run->ring_buffers[run->ring_buf_kvm_ptr];	
		run->used_buffers--;
		if(!run->used_buffers)
		{
			kvm_err("Buffer underflow or Log file exhausted\n");
			return 0;
		}
		vcpu->log_offset = 0;
		vcpu->log_rec_len = 0;
	}
		

	log_type = (buf+vcpu->log_offset)[0];

	data_len = (buf+vcpu->log_offset+1);

	vcpu->log_rec_len = *data_len;

	switch(log_type)
	{
		case KVM_RR_PIO_IN:
		case KVM_RR_RDTSC:
		case KVM_RR_MMIO_IN:
		case KVM_RR_HEADER:
		case KVM_RR_REGS_SET:
		case KVM_RR_REQ:
			// account only type and length
			vcpu->log_rec_len += 3;
			break;
		case KVM_RR_EXT_INT:
			//account for ts , type and lenght
			vcpu->log_rec_len += (3 + sizeof(struct kvm_rr_ts));
			break;
		default:
			kvm_err("Invalid log type %d\n",log_type);
			return -1;
	}
	// just for cross checking count num of recs. 
	vcpu->num_recs++;
	return  log_type;
}
EXPORT_SYMBOL_GPL(read_log);
*/


// this function will take log type, vcpu(for timestamp), data_length  and
// void pointer to data, pointer will be deferenced according 
// to log type. 
//
// 0 - success
// 1 - failure
int write_log(u8 log_type, struct kvm_vcpu *vcpu, u16 data_len, 
				void *data )
{
	//struct kvm_rr_ts *ts = &vcpu->rr_ts;
	//size_t count = KVM_RR_LOG_SIZE(data_len);
	//int ret;
	//int offset = 0,fil_size;
	//int flag=0;

	//struct kvm_run *run=vcpu->run;

	if(!kvm_record)	
		return 1;

	//edit by rsr : just fot debug.... Should be delete later...
	
	switch (log_type) {
	case KVM_RR_RDTSC:	{
		/*
		struct kvm_rr_rdtsc *rdtsc_rr_log;
		rdtsc_rr_log = data;
		u64 tsc = rdtsc_rr_log->tsc;

		printk("<1>""RDTSC : " \
			"log type: %d . " \
			"data length: %d. " \
			"data(tsc): %lld . " \
			"\n", log_type , data_len , tsc );
		*/		
		break;
	}
	case KVM_RR_PIO_IN: {
		
		struct kvm_rr_pio_in *pio_rr_log;
		pio_rr_log = data;
		pio_rr_log->data[ vcpu->arch.pio.count * vcpu->arch.pio.size ] = '\0';
		printk( "VCPU %d :", vcpu->vcpu_id );
		printk( "PIO IN: " \
				"data length: %u, " \
				"end position: %lu, " \
				"data(pio): %s, " \
				"time_stamp= %llu" \
				"\n", data_len, vcpu->arch.pio.count * vcpu->arch.pio.size, pio_rr_log->data , pio_rr_log->time_stamp); 
		
		break;
	}
	case KVM_RR_PIO_OUT: {
		struct kvm_rr_pio_out *pio_rr_log = data;
		printk( "VCPU %d :", vcpu->vcpu_id );
		printk("PIO OUT: time_stamp= %llu\n", pio_rr_log->time_stamp); 		
		
		break;
	}
	case KVM_RR_MMIO_IN: {
		
		struct kvm_rr_mmio_in *mmio_rr_log;
		char rsr_out[9];
		mmio_rr_log = data;
		memset( rsr_out , 0 , 9 );
		memcpy( rsr_out , mmio_rr_log->data , 8 );
		rsr_out[8] = 0;
		printk( "VCPU %d :", vcpu->vcpu_id );
		printk( "MMIO IN, Data: %s  | " \
				"Address: 0x%llx time_stamp= %llu \n" , rsr_out , mmio_rr_log->mmio_phys_addr, mmio_rr_log->time_stamp);
		
		break;
	}
	case KVM_RR_MMIO_OUT: {
		struct kvm_rr_mmio_out *mmio_rr_log;
		mmio_rr_log = data;
		printk( "VCPU %d :", vcpu->vcpu_id );
		printk("MMIO OUT, time_stamp= %llu \n", mmio_rr_log->time_stamp);
		break;
	}
	case KVM_RR_EXT_INT: {
		/*
		struct kvm_rr_ext_int * ext_int_rr_log;
		ext_int_rr_log = data;
		printk( "Interrupt : " \
				"Interrupt vector: %u, " \
				"IRQ number: %u, " \
				"IRQ count: %d ,"
				"ts.rip: %llu,"\
				"ts.ecx: %llu,"\
				"ts.bc: %llu"
				"\n", ext_int_rr_log->int_vec, \
				ext_int_rr_log->irq, ext_int_rr_log->irq_count , ts->rip , ts->rcx , ts->br_count); 
		*/
		break;
	}
	default:
		return 1;
	}

	return 0;

	//end rsr

	
//To be continue....
/*
	offset = vcpu->log_offset % KVM_MAX_LOG_SIZE;
	// check if new block has to be created or not

	int old_no_blocks = vcpu->log_offset / KVM_MAX_LOG_SIZE;
	int new_no_blocks = (vcpu->log_offset + KVM_RR_LOG_DATA \
				+ data_len) / KVM_MAX_LOG_SIZE ;	 
	if( new_no_blocks > old_no_blocks )
	{
		// fill the log buffer with enough zeros to complete
		// the old block
		kvm_debug("new block fil %d %llu \n", fil_size, vcpu->log_offset+fil_size);
		fil_size = KVM_MAX_LOG_SIZE - (vcpu->log_offset % KVM_MAX_LOG_SIZE);
	
		memset(run->ring_buffers[run->ring_buf_kvm_ptr]+offset, 0, fil_size);
		
		run->invalid_exit_reason = 1;
		run->ring_buf_kvm_ptr = ((run->ring_buf_kvm_ptr+1)%KVM_RR_RING_BUF_SIZE);
		buf = run->ring_buffers[run->ring_buf_kvm_ptr];
		run->used_buffers++;
		if(run->used_buffers == KVM_RR_RING_BUF_SIZE)
		{
			kvm_err("buffer overflow \n");
			vcpu->is_recording = 0;
			return 1;
		}

		// update the new file position
		vcpu->log_offset += fil_size;
		offset = 0;
		
	}

log_copy:
	vcpu->num_recs++;	
	switch(log_type)
	{
		case KVM_RR_RDTSC:
		{
			// has data 
			// it is alway synchronous, i.e. we can rely on 
			// CPU execution to generate this at the right time
			// rather than we stopping it. So no time stamp is
			// required for this event.

			//
			memcpy(buf+offset+KVM_RR_LOG_TYPE, (void *)(&log_type),\
							sizeof(u8));
			memcpy(buf+offset+KVM_RR_LOG_DATA_LEN, (void *)(&data_len),\
							sizeof(u16));
			memcpy(buf+offset+KVM_RR_LOG_TS, data, data_len);

			vcpu->prev_log_data_offset = offset+KVM_RR_LOG_TS;

			count -= sizeof(struct kvm_rr_ts); 
		
			vcpu->log_offset += count;
			return 0;
		}
		case KVM_RR_PIO_IN:
		case KVM_RR_REQ:
		{
			//
			memcpy(buf+offset+KVM_RR_LOG_TYPE, (void *)(&log_type),\
							sizeof(u8));
			memcpy(buf+offset+KVM_RR_LOG_DATA_LEN, (void *)(&data_len),\
                                                        sizeof(u16));
	
			memcpy(buf+offset+KVM_RR_LOG_TS, data, data_len);

			vcpu->prev_log_data_offset = offset+KVM_RR_LOG_TS;

			count -= sizeof(struct kvm_rr_ts);

			vcpu->log_offset += count;
			return 0;
		}	
		case KVM_RR_MMIO_IN:
		{
			memcpy(buf+offset+KVM_RR_LOG_TYPE, (void *)(&log_type),\
							sizeof(u8));
			memcpy(buf+offset+KVM_RR_LOG_DATA_LEN, (void *)(&data_len),\
                                                        sizeof(u16));
			
			memcpy(buf+offset+KVM_RR_LOG_TS, data, data_len);

			vcpu->prev_log_data_offset = offset+KVM_RR_LOG_TS;

			count -= sizeof(struct kvm_rr_ts);
		
			vcpu->log_offset += count;
			return 0;
		}
		case KVM_RR_REGS_SET:
		{
			memcpy(buf+offset+KVM_RR_LOG_TYPE, (void *)(&log_type),\
							sizeof(u8));
			memcpy(buf+offset+KVM_RR_LOG_DATA_LEN, (void *)(&data_len),\
                                                        sizeof(u16));
		
			memcpy(buf+offset+KVM_RR_LOG_TS, data, data_len);

			vcpu->prev_log_data_offset = offset+KVM_RR_LOG_TS;

			count -= sizeof(struct kvm_rr_ts);
		
			vcpu->log_offset += count;
			return 0;
		}
	
		case KVM_RR_EXT_INT:
		{
			// we need to record the time stamp !
			
			memcpy(buf+offset+KVM_RR_LOG_TYPE, (void *)(&log_type),\
							sizeof(u8));
			memcpy(buf+offset+KVM_RR_LOG_DATA_LEN, (void *)(&data_len),\
                                                        sizeof(u16));
			memcpy(buf+offset+KVM_RR_LOG_TS, (void *)ts,\
                                                         sizeof(struct kvm_rr_ts));
			
			memcpy(buf+offset+KVM_RR_LOG_DATA, data, data_len);
	
			vcpu->prev_log_data_offset = offset+KVM_RR_LOG_DATA;

			vcpu->log_offset += count;
			return 0;

		}
		case KVM_RR_HEADER:
		{
			memcpy(buf+offset+KVM_RR_LOG_TYPE, (void *)(&log_type),\
							sizeof(u8));		
			memcpy(buf+offset+KVM_RR_LOG_DATA_LEN, (void *)(&data_len),\
                                                        sizeof(u16));
			
			memcpy(buf+offset+KVM_RR_LOG_TS, data, data_len);
			
			vcpu->prev_log_data_offset = offset+KVM_RR_LOG_TS;

			count -= sizeof(struct kvm_rr_ts);

			vcpu->log_offset += count;
			return 0;
		}


		defualt:
		{
			kvm_err("invalid log type \n");
			return 1;
		}

	}

*/
}
EXPORT_SYMBOL_GPL(write_log);

