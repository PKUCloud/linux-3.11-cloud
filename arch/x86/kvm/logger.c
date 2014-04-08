/* #define DEBUG */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>	/* printk() */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/types.h>	/* size_t */
#include <linux/proc_fs.h>
#include <linux/fcntl.h>	/* O_ACCMODE */
#include <linux/aio.h>
#include <asm/uaccess.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/types.h>
#include <linux/device.h>

#include "logger.h"

int logger_major = LOGGER_MAJOR;          //device major number
int logger_quantum = LOGGER_QUANTUM;         //quantum size
int logger_print_time = PRINT_TIME;          //print timestamp

module_param(logger_major, int, 0);
module_param(logger_quantum, int, 0);
module_param(logger_print_time, int, 1);
MODULE_LICENSE("GPL");

struct logger_dev logger_dev;        //the device struct

//declare two cache pointer
struct kmem_cache *data_cache;    //data page cache
struct kmem_cache *quantum_cache;   //for struct logger_quantum

struct proc_dir_entry *entry;

extern bool kvm_record;	/*if recording is running */
// open function
int logger_open(struct inode *inode, struct file *filp)
{
	struct logger_dev *dev;
	dev = container_of(inode->i_cdev, struct logger_dev, cdev);

	filp->private_data = dev;

	return 0;      //success
}


//close function
int logger_release(struct inode *inode, struct file *filp)
{
	return 0;
}


/* read function of the file_operations
 * does not return data really
 * just return struct quantum_info to the user-space to tell the info 
 * about next quantum to read. Then the user-space will mmap() to read
 * the quantum. This function will be blocked if the global out_list is
 * empty.
 */
ssize_t logger_read(struct file *filp, char __user *buf, size_t count,
	loff_t *f_pos)
{
	struct logger_dev *dev = filp->private_data;
	/*despite what count is, ret is the size of quantum_info.
	 * In the case of fread(), it will always set count to 4096 (buffer).
	 */
	int ret = sizeof(struct quantum_info);
	struct quantum_info qinfo;
	struct logger_quantum *ptr;

	spin_lock(&dev->dev_lock);
	while(1) {
		if(likely(dev->head)) {
			/* the global out_list is not empty
			 * so there are quantums to be transfered
			 */
			 ptr = dev->head;
			 qinfo.vcpu_id = ptr->vcpu_id;
			 qinfo.quantum_size = ptr->quantum_size;
			 goto out;
		} else {
			/* the global out_list is empty now
			 * either to wait for data or wait for a flush command
			 */
			if(unlikely(dev->state == FLUSHED)) {
			 	/* now there is no data in the out_list and the state
			 	 * is FLUSHED. It means the record is terminated.
			 	 */
			 	 ret = 0;
			 	 dev->state = NORMAL;
			 	 goto out;
			} else {
			 	if(unlikely(filp->f_flags & O_NONBLOCK)) {
				 	ret = -EAGAIN;
				 	goto out;
				}
				 /* block */
				spin_unlock(&dev->dev_lock);
				 /* sometimes maybe even after a flush, there is no data in out_list. In this situation
				  * we need to wake up it, too.
				  */
				if(wait_event_interruptible(dev->queue, (dev->head != NULL || dev->state == FLUSHED)))
					return -ERESTARTSYS;
				spin_lock(&dev->dev_lock);
			}
		}
	}

	
out:
	spin_unlock(&dev->dev_lock);
	
	if(likely(ret > 0)) {
		/* transfer qinfo to user-space */
		if(copy_to_user(buf, &qinfo, sizeof(qinfo))) {
			return -EFAULT;
		}
		*f_pos += ret;	/* does the delta have to be the same as ret? */
	}
	return ret;
}


//write function
ssize_t logger_write(struct file *filp, const char __user *buf, size_t count,
	loff_t *f_pos)
{
	return count;
}


//mmap is available, but confined in a different file mmap.c
extern int logger_mmap(struct file *filp, struct vm_area_struct *vma);


/*
* The ioctl() implementation
*/
long logger_ioctl(struct file *filp,
	unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	int i, size;
	struct logger_dev *dev = filp->private_data;
	struct vcpu_quantum *vq;
	struct logger_quantum *ptr;

	if(_IOC_TYPE(cmd) != LOGGER_IOC_MAGIC) return -ENOTTY;

	switch(cmd) {
	/* If recording is still running, just return immediately,
	 * otherwise, moves all the vcpu_quantums's quantum to the out_list
	 * and flush them out to user-space
	 */
	case LOGGER_FLUSH:
		if(kvm_record)
			return -EPERM;	/* operation not permitted */
		spin_lock(&dev->dev_lock);
		dev->state = FLUSHED;
		for(i = 0; i < MAX_VCPU; ++i) {
			vq = &dev->quantums[i];
			if(vq->head) {
				assert(vq->head == vq->tail && vq->vcpu_id == vq->head->vcpu_id);
				size = vq->str - (char*)(vq->head->data);
				if(size > 0) {
					/* move it to the out_list */
					ptr = vq->head;
					assert(ptr->next == NULL);
					vq->head = vq->tail = NULL;
					vq->str = vq->end = NULL;
					ptr->quantum_size = size;
					if(logger_dev.head == NULL) {
						logger_dev.head = ptr;
						logger_dev.tail = ptr;
					} else {
						logger_dev.tail->next = ptr;
						logger_dev.tail = ptr;
					}
					wake_up_interruptible(&dev->queue);
				}
			}
		}
		wake_up_interruptible(&dev->queue);
		spin_unlock(&dev->dev_lock);
		break;

	default:
		return -ENOTTY;
	}
	return ret;
}

//fops
struct file_operations logger_fops = {
	.owner =	THIS_MODULE,
	.read = 	logger_read,
	.write =	logger_write,
	.open =		logger_open,
	.release = 	logger_release,
	.mmap = logger_mmap,
	.unlocked_ioctl = logger_ioctl
};



static int logger_setup_cdev(struct logger_dev *dev)
{
	int err, devno = MKDEV(logger_major, 0);

	cdev_init(&dev->cdev, &logger_fops);
	dev->cdev.owner = THIS_MODULE;
	dev->cdev.ops = &logger_fops;
	err = cdev_add(&dev->cdev, devno, 1);

	if(err) {
		pr_err("Err: %d fail to cdev_add() for logger\n", err);
		goto out;
	}

	dev->logger_class = class_create(THIS_MODULE, "logger");
	if(IS_ERR(dev->logger_class)) {
		pr_err("Err: fail to class_create() for logger\n");
		err = -1;
		goto fail_create_class;
	}
	device_create(dev->logger_class, NULL, devno, NULL, "logger");

	return 0;

fail_create_class:
	cdev_del(&dev->cdev);
out:
	return err;
}






/**
* interfaces for seq_file
* just show the data of the out_list
*/
static void *logger_seq_start(struct seq_file *s, loff_t *pos)
{
	int i = *pos;
	struct logger_quantum *ptr;

	spin_lock(&logger_dev.dev_lock);

	ptr = logger_dev.head;
	while(ptr != NULL && i > 0){
		ptr = ptr->next;
		i--;
	}

	if(i > 0 || !ptr)
		return NULL;
	else return ptr;
}


static void *logger_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	int i = ++(*pos);
	struct logger_quantum *ptr = logger_dev.head;

	while(ptr != NULL && i > 0){
		ptr = ptr->next;
		i--;
	}

	if(i > 0 || !ptr)
		return NULL;
	else return ptr;
}

static void logger_seq_stop(struct seq_file *s, void *v)
{
	spin_unlock(&logger_dev.dev_lock);
}

static int logger_seq_show(struct seq_file *s, void *v)
{
	struct logger_quantum *ptr = v;
	int i = 0;
	char *str = (char*)ptr->data;

	if(ptr->vcpu_id != 0) return 0;

	seq_puts(s, "<start>=================\n");
	for(i = 0; i < 4096; i++)
		seq_putc(s, str[i]);
	seq_puts(s, "\n<end>====================\n");

	return 0;
}


static struct seq_operations logger_seq_ops = {
	.start = logger_seq_start,
	.next = logger_seq_next,
	.stop = logger_seq_stop,
	.show = logger_seq_show,
};

static int logger_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &logger_seq_ops);
}

static struct file_operations logger_file_ops = {
	.owner = THIS_MODULE,
	.open = logger_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

/**
end of interfaces for seq_file
*/



/*init struct logger_dev */
static void logger_dev_init(struct logger_dev *dev)
{
	int i;
	if(dev) {
		memset(dev, 0, sizeof(*dev));
		spin_lock_init(&dev->dev_lock);
		init_waitqueue_head(&dev->queue);
		dev->state = NORMAL;

		for(i = 0; i < MAX_VCPU; ++i) {
			dev->quantums[i].vcpu_id = i;
		}
	}
}



//init function
int logger_init(void)
{
	int result;
	dev_t dev = MKDEV(logger_major, 0);

	if(logger_major)
		result = register_chrdev_region(dev, 1, "logger");
	else {
		result = alloc_chrdev_region(&dev, 0, 1, "logger");
		logger_major = MAJOR(dev);
	}

	if(result < 0) {
		pr_err("Err: %d fail to register_chrdev_region() for logger\n", result);
		goto out;
	}


	logger_dev_init(&logger_dev);


	//create cache   //3.11 is different from 2.6
	data_cache = kmem_cache_create("logger_data", logger_quantum,
		0, 0, NULL);        //no ctor/dtor  SLAB_HWCACHE_ALIGN??
	if(!data_cache) {
		result = -ENOMEM;
		pr_err("Err: %d fail to kmem_cache_create() for logger\n", result);
		goto fail_create_cache;
	}

	quantum_cache = kmem_cache_create("logger_quantum", sizeof(struct logger_quantum),
		0, 0, NULL);
	if(!quantum_cache) {
		result = -ENOMEM;
		pr_err("Err: %d fail to kmem_cache_create() for logger\n", result);
		goto fail_create_cache;
	}

	//setup cdev
	result = logger_setup_cdev(&logger_dev);
	if(result)
		goto fail_add_dev;


	//init the seq interface
	entry = proc_create("logger", 0, NULL, &logger_file_ops);
	if(!entry) {
		result = -1;
		pr_err("Err: fail to proc_create() for logger\n");
		goto fail_add_proc;
	}

	logger_dev.print_time = logger_print_time;

	pr_debug("logger init successfully\n");
	result = 0;
	goto out;	/* success */

fail_add_proc:
	cdev_del(&logger_dev.cdev);
	device_destroy(logger_dev.logger_class, MKDEV(logger_major, 0));
	class_destroy(logger_dev.logger_class);

fail_add_dev:
	kmem_cache_destroy(quantum_cache);

fail_create_cache:
	if(data_cache)
		kmem_cache_destroy(data_cache);
	unregister_chrdev_region(dev, 1);

out:
	return result;
}



/*free the memory */
void logger_trim(struct logger_dev *dev)
{
	struct logger_quantum *cur, *next;
	int i;
	
	/* release the out_list */
	cur = dev->head;
	while(cur) {
		next = cur->next;
		kmem_cache_free(data_cache, cur->data);
		kmem_cache_free(quantum_cache, cur);
		cur = next;
	}
	dev->head = NULL;
	dev->tail = NULL;
	/*
	logger_dev.str = logger_dev.end = NULL;
	logger_dev.size = 0;
	*/
	
	/* release the vcpu_quantums */
	for(i = 0; i < MAX_VCPU; ++i) {
		struct vcpu_quantum *vq;

		vq = dev->quantums + i;
		cur = vq->head;
		while(cur) {
			next = cur->next;
			kmem_cache_free(data_cache, cur->data);
			kmem_cache_free(quantum_cache, cur);
			cur = next;
		}
		vq->str = NULL;
		vq->end = NULL;
		vq->head = NULL;
		vq->tail = NULL;
	}
}

void logger_cleanup(void)
{
	if(entry)
		remove_proc_entry("logger", NULL);   //remove the /proc/logger at first

	cdev_del(&logger_dev.cdev);
	
	spin_lock(&logger_dev.dev_lock);

	logger_trim(&logger_dev);

	if(data_cache)
		kmem_cache_destroy(data_cache);

	if(quantum_cache)
		kmem_cache_destroy(quantum_cache);

	spin_unlock(&logger_dev.dev_lock);

	if(logger_dev.logger_class) {
		device_destroy(logger_dev.logger_class, MKDEV(logger_major, 0));
		class_destroy(logger_dev.logger_class);
	}

	unregister_chrdev_region(MKDEV(logger_major, 0), 1);

	pr_debug("logger exit successfully\n");
}




/* this function should not be used now. It is obsolete
 *Called when there is no rom to store log, alloc a new struct logger_quantum and a page
 *Before calling this function, you should get the lock
 */
 /*
int logger_alloc_page(void)
{
	struct logger_quantum *ptr;
	int result = 0;

	ptr = kmem_cache_alloc(quantum_cache, GFP_ATOMIC);
	if(!ptr) {
		result = -ENOMEM;
		pr_err("Err: %d fail to kmem_cache_alloc() for logger\n", result);
		goto out;
	}

	memset(ptr, 0, sizeof(*ptr));

	ptr->data = kmem_cache_alloc(data_cache, GFP_ATOMIC);
	if(!ptr->data) {
		kmem_cache_free(quantum_cache, ptr);
		result = -ENOMEM;
		pr_err("Err: %d fail to kmem_cache_alloc() for logger\n", result);
		goto out;
	}

	memset(ptr->data, 0, logger_quantum);
	if(logger_dev.head == NULL) {
		logger_dev.head = logger_dev.tail = ptr;
	}else {
		logger_dev.tail->next = ptr;
		logger_dev.tail = ptr;
	}

	logger_dev.str = (char*)ptr->data;
	logger_dev.end = logger_dev.str + logger_quantum;

out:
	return result;
}
*/


/* this function is called when there is no room for a vcpu_quantum to store a log
 * it first allocates a new quantum to the vcpu_quantum
 * then it moves the former full page (if exists) to the global out_list
 */
int logger_alloc_move_page(struct vcpu_quantum *vq)
{
	struct logger_quantum *ptr;
	int ret = 0;

	ptr = kmem_cache_alloc(quantum_cache, GFP_ATOMIC);
	if(!ptr) {
		ret = -ENOMEM;
		pr_err("Err: %d fail to kmem_cache_alloc() for logger\n", ret);
		goto move;
	}

	memset(ptr, 0, sizeof(*ptr));	/* ptr->quantum_size is set to 0 */

	ptr->data = kmem_cache_alloc(data_cache, GFP_ATOMIC);
	if(!ptr->data) {
		kmem_cache_free(quantum_cache, ptr);
		ret = -ENOMEM;
		pr_err("Err: %d fail to kmem_cache_alloc() for logger\n", ret);
		goto move;
	}

	memset(ptr->data, 0, logger_quantum);
	ptr->vcpu_id = vq->vcpu_id;
	vq->str = (char*)ptr->data;
	vq->end = vq->str + logger_quantum;
	if(vq->head == NULL) {
		vq->head = ptr;
		vq->tail = ptr;
	} else {
		vq->tail->next = ptr;
		vq->tail = ptr;
		goto move;
	}

	return ret;

move:
	if(vq->head == NULL) 
		return ret;
	/* move the head quantum to the global out_list */
	ptr = vq->head;
	vq->head = vq->head->next;
	if(vq->tail == ptr) {	/* there is only one page */
		vq->tail = vq->head;
		assert(vq->tail == NULL && vq->str != ptr->data);
	}
	assert(vq->str != ptr->data);
	ptr->next = NULL;
	ptr->quantum_size = logger_quantum;	/* it is a full quantum */
	spin_lock(&logger_dev.dev_lock);
	if(logger_dev.head == NULL) {
		logger_dev.head = ptr;
		logger_dev.tail = ptr;
	} else {
		logger_dev.tail->next = ptr;
		logger_dev.tail = ptr;
	}
	wake_up_interruptible(&logger_dev.queue);
	spin_unlock(&logger_dev.dev_lock);

	return ret;
}


static noinline_for_stack
int skip_atoi(const char **s)
{
	int i = 0;

	while (isdigit(**s))
		i = i*10 + *((*s)++) - '0';

	return i;
}



/* Decimal conversion is by far the most typical, and is used
 * for /proc and /sys data. This directly impacts e.g. top performance
 * with many processes running. We optimize it for speed
 * using ideas described at <http://www.cs.uiowa.edu/~jones/bcd/divide.html>
 * (with permission from the author, Douglas W. Jones).
 */

#if BITS_PER_LONG != 32 || BITS_PER_LONG_LONG != 64
/* Formats correctly any integer in [0, 999999999] */
static noinline_for_stack
char *put_dec_full9(char *buf, unsigned q)
{
	unsigned r;

	/*
	 * Possible ways to approx. divide by 10
	 * (x * 0x1999999a) >> 32 x < 1073741829 (multiply must be 64-bit)
	 * (x * 0xcccd) >> 19     x <      81920 (x < 262149 when 64-bit mul)
	 * (x * 0x6667) >> 18     x <      43699
	 * (x * 0x3334) >> 17     x <      16389
	 * (x * 0x199a) >> 16     x <      16389
	 * (x * 0x0ccd) >> 15     x <      16389
	 * (x * 0x0667) >> 14     x <       2739
	 * (x * 0x0334) >> 13     x <       1029
	 * (x * 0x019a) >> 12     x <       1029
	 * (x * 0x00cd) >> 11     x <       1029 shorter code than * 0x67 (on i386)
	 * (x * 0x0067) >> 10     x <        179
	 * (x * 0x0034) >>  9     x <         69 same
	 * (x * 0x001a) >>  8     x <         69 same
	 * (x * 0x000d) >>  7     x <         69 same, shortest code (on i386)
	 * (x * 0x0007) >>  6     x <         19
	 * See <http://www.cs.uiowa.edu/~jones/bcd/divide.html>
	 */
	r      = (q * (uint64_t)0x1999999a) >> 32;
	*buf++ = (q - 10 * r) + '0'; /* 1 */
	q      = (r * (uint64_t)0x1999999a) >> 32;
	*buf++ = (r - 10 * q) + '0'; /* 2 */
	r      = (q * (uint64_t)0x1999999a) >> 32;
	*buf++ = (q - 10 * r) + '0'; /* 3 */
	q      = (r * (uint64_t)0x1999999a) >> 32;
	*buf++ = (r - 10 * q) + '0'; /* 4 */
	r      = (q * (uint64_t)0x1999999a) >> 32;
	*buf++ = (q - 10 * r) + '0'; /* 5 */
	/* Now value is under 10000, can avoid 64-bit multiply */
	q      = (r * 0x199a) >> 16;
	*buf++ = (r - 10 * q)  + '0'; /* 6 */
	r      = (q * 0xcd) >> 11;
	*buf++ = (q - 10 * r)  + '0'; /* 7 */
	q      = (r * 0xcd) >> 11;
	*buf++ = (r - 10 * q) + '0'; /* 8 */
	*buf++ = q + '0'; /* 9 */
	return buf;
}
#endif

/* Similar to above but do not pad with zeros.
 * Code can be easily arranged to print 9 digits too, but our callers
 * always call put_dec_full9() instead when the number has 9 decimal digits.
 */
static noinline_for_stack
char *put_dec_trunc8(char *buf, unsigned r)
{
	unsigned q;

	/* Copy of previous function's body with added early returns */
	while (r >= 10000) {
		q = r + '0';
		r  = (r * (uint64_t)0x1999999a) >> 32;
		*buf++ = q - 10*r;
	}

	q      = (r * 0x199a) >> 16;	/* r <= 9999 */
	*buf++ = (r - 10 * q)  + '0';
	if (q == 0)
		return buf;
	r      = (q * 0xcd) >> 11;	/* q <= 999 */
	*buf++ = (q - 10 * r)  + '0';
	if (r == 0)
		return buf;
	q      = (r * 0xcd) >> 11;	/* r <= 99 */
	*buf++ = (r - 10 * q) + '0';
	if (q == 0)
		return buf;
	*buf++ = q + '0';		 /* q <= 9 */
	return buf;
}

/* There are two algorithms to print larger numbers.
 * One is generic: divide by 1000000000 and repeatedly print
 * groups of (up to) 9 digits. It's conceptually simple,
 * but requires a (unsigned long long) / 1000000000 division.
 *
 * Second algorithm splits 64-bit unsigned long long into 16-bit chunks,
 * manipulates them cleverly and generates groups of 4 decimal digits.
 * It so happens that it does NOT require long long division.
 *
 * If long is > 32 bits, division of 64-bit values is relatively easy,
 * and we will use the first algorithm.
 * If long long is > 64 bits (strange architecture with VERY large long long),
 * second algorithm can't be used, and we again use the first one.
 *
 * Else (if long is 32 bits and long long is 64 bits) we use second one.
 */

#if BITS_PER_LONG != 32 || BITS_PER_LONG_LONG != 64

/* First algorithm: generic */

static
char *put_dec(char *buf, unsigned long long n)
{
	if (n >= 100*1000*1000) {
		while (n >= 1000*1000*1000)
			buf = put_dec_full9(buf, do_div(n, 1000*1000*1000));
		if (n >= 100*1000*1000)
			return put_dec_full9(buf, n);
	}
	return put_dec_trunc8(buf, n);
}

#else

/* Second algorithm: valid only for 64-bit long longs */

/* See comment in put_dec_full9 for choice of constants */
static noinline_for_stack
void put_dec_full4(char *buf, unsigned q)
{
	unsigned r;
	r      = (q * 0xccd) >> 15;
	buf[0] = (q - 10 * r) + '0';
	q      = (r * 0xcd) >> 11;
	buf[1] = (r - 10 * q)  + '0';
	r      = (q * 0xcd) >> 11;
	buf[2] = (q - 10 * r)  + '0';
	buf[3] = r + '0';
}

/*
 * Call put_dec_full4 on x % 10000, return x / 10000.
 * The approximation x/10000 == (x * 0x346DC5D7) >> 43
 * holds for all x < 1,128,869,999.  The largest value this
 * helper will ever be asked to convert is 1,125,520,955.
 * (d1 in the put_dec code, assuming n is all-ones).
 */
static
unsigned put_dec_helper4(char *buf, unsigned x)
{
        uint32_t q = (x * (uint64_t)0x346DC5D7) >> 43;

        put_dec_full4(buf, x - q * 10000);
        return q;
}

/* Based on code by Douglas W. Jones found at
 * <http://www.cs.uiowa.edu/~jones/bcd/decimal.html#sixtyfour>
 * (with permission from the author).
 * Performs no 64-bit division and hence should be fast on 32-bit machines.
 */
static
char *put_dec(char *buf, unsigned long long n)
{
	uint32_t d3, d2, d1, q, h;

	if (n < 100*1000*1000)
		return put_dec_trunc8(buf, n);

	d1  = ((uint32_t)n >> 16); /* implicit "& 0xffff" */
	h   = (n >> 32);
	d2  = (h      ) & 0xffff;
	d3  = (h >> 16); /* implicit "& 0xffff" */

	q   = 656 * d3 + 7296 * d2 + 5536 * d1 + ((uint32_t)n & 0xffff);
	q = put_dec_helper4(buf, q);

	q += 7671 * d3 + 9496 * d2 + 6 * d1;
	q = put_dec_helper4(buf+4, q);

	q += 4749 * d3 + 42 * d2;
	q = put_dec_helper4(buf+8, q);

	q += 281 * d3;
	buf += 12;
	if (q)
		buf = put_dec_trunc8(buf, q);
	else while (buf[-1] == '0')
		--buf;

	return buf;
}

#endif



//return the length of the total output
static noinline_for_stack
int number(struct vcpu_quantum *vq, unsigned long long num,
	struct printf_spec spec)
{
	static const char digits[16] = "0123456789ABCDEF";

	char tmp[66];
	char sign;
	char locase;
	int need_pfx = ((spec.flags & SPECIAL) && spec.base != 10);
	int i, length = 0;
	bool is_zero = num == 0LL;

	locase = (spec.flags & SMALL);
	if(spec.flags & LEFT)
		spec.flags &= ~ZEROPAD;
	sign = 0;
	if(spec.flags & SIGN) {
		if((signed long long)num < 0) {
			sign = '-';
			num = -(signed long long)num;
			spec.field_width--;
		} else if(spec.flags & PLUS) {
			sign = '+';
			spec.field_width--;
		}else if(spec.flags & SPACE) {
			sign = ' ';
			spec.field_width--;
		} 
	}
	if(need_pfx) {
		if(spec.base == 16)
			spec.field_width -= 2;
		else if(!is_zero)
			spec.field_width--;
	}

	//generate full string in tmp[], in reverse order
	i = 0;
	if(num < spec.base)
		tmp[i++] = digits[num] | locase;
	else if(spec.base != 10) {
		int mask = spec.base - 1;
		int shift = 3;

		if(spec.base == 16)
			shift = 4;
		do {
			tmp[i++] = (digits[((unsigned char)num) & mask] | locase);
			num >>= shift;
		}while (num);
	} else {
		//base 10
		i = put_dec(tmp, num) - tmp;
	}

	if(i > spec.precision)
		spec.precision = i;

	//leading space padding
	spec.field_width -= spec.precision;
	if(!(spec.flags & (ZEROPAD + LEFT))) {
		while(--spec.field_width >= 0) {
			if(unlikely(vq->str >= vq->end)) 
				if(unlikely(logger_alloc_move_page(vq)))
					return length;
			*(vq->str) = ' ';
			++(vq->str);
			++length;
		}
	}

	//signed
	if(sign) {
		if(unlikely(vq->str >= vq->end)) 
			if(unlikely(logger_alloc_move_page(vq)))
				return length;
		*(vq->str) = sign;
		++(vq->str);
		++length;
	}

	//"0x" or "0" prefix
	if(need_pfx) {
		if(spec.base == 16 || !is_zero) {
			if(unlikely(vq->str >= vq->end)) 
				if(unlikely(logger_alloc_move_page(vq)))
					return length;
			*(vq->str) = '0';
			++(vq->str);
			++length;
		}
		if(spec.base == 16) {
			if(unlikely(vq->str >= vq->end)) 
				if(unlikely(logger_alloc_move_page(vq)))
					return length;
			*(vq->str) = ('X' | locase);
			++(vq->str);
			++length;
		}
	}

	//zero or space padding
	if(!(spec.flags & LEFT)) {
		char c = (spec.flags & ZEROPAD) ? '0' : ' ';
		while(--spec.field_width >= 0) {
			if(unlikely(vq->str >= vq->end)) 
				if(unlikely(logger_alloc_move_page(vq)))
					return length;
			*(vq->str) = c;
			++(vq->str);
			++length;
		}
	}

	//even more zero padding
	while(i <= --spec.precision) {
		if(unlikely(vq->str >= vq->end)) 
			if(unlikely(logger_alloc_move_page(vq)))
				return length;
		*(vq->str) = '0';
		++(vq->str);
		++length;
	}

	//actual digits of result
	while(--i >= 0) {
		if(unlikely(vq->str >= vq->end)) 
			if(unlikely(logger_alloc_move_page(vq)))
				return length;
		*(vq->str) = tmp[i];
		++(vq->str);
		++length;
	}
	

	//trailing space padding
	while(--spec.field_width >= 0) {
		if(unlikely(vq->str >= vq->end)) 
			if(unlikely(logger_alloc_move_page(vq)))
				return length;
		*(vq->str) = ' ';
		++(vq->str);
		++length;
	}

	return length;
}


//return the length of the total output
static noinline_for_stack
int string(struct vcpu_quantum *vq, const char *s, struct printf_spec spec)
{
	int len, i, length = 0;
 	/* what does it mean? */
	if((unsigned long)s < PAGE_SIZE) {
		s = "(null)";
		printk(KERN_ALERT "(unsigned long)s < PAGE_SIZE is true!!! Check line #828 in logger.c\n");
	}
		

	len = strnlen(s, spec.precision);

	if(!(spec.flags & LEFT)) {
		while(len < spec.field_width--) {
			if(unlikely(vq->str >= vq->end)) 
				if(unlikely(logger_alloc_move_page(vq)))
					return length;
			*(vq->str) = ' ';
			++(vq->str);
			++length;
		}
	}
	for (i = 0; i < len; ++i) {
		if(unlikely(vq->str >= vq->end)) 
			if(unlikely(logger_alloc_move_page(vq)))
				return length;
		*(vq->str) = *s;
		++(vq->str);
		++s;
	}
	length += len;

	while(len < spec.field_width--) {
		if(unlikely(vq->str >= vq->end)) 
			if(unlikely(logger_alloc_move_page(vq)))
				return length;
		*(vq->str) = ' ';
		++(vq->str);
		++length;
	}

	return length;
}






/*
* @fmt: the format string
* @type of the token returned
* @flags: various flags such as +, -, # tokens..
* @field_width: overwritten width
* @base: base of the number (octal, hex, ...)
* @precision: precision of a number
* @qualifier: qualifier of a number (long, size_t, ...)
*/
static noinline_for_stack
int format_decode(const char *fmt, struct printf_spec *spec)
{
	const char *start = fmt;

	//we have read the field width from the parameter
	if(spec->type == FORMAT_TYPE_WIDTH) {
		if(spec->field_width < 0) {
			spec->field_width = -spec->field_width;
			spec->flags |= LEFT;
		}
		spec->type = FORMAT_TYPE_NONE;
		goto precision;
	}

	//we have read the precision from the parameter
	if(spec->type == FORMAT_TYPE_PRECISION) {
		if(spec->precision < 0)
			spec->precision = 0;

		spec->type = FORMAT_TYPE_NONE;
		goto qualifier;
	}

	//by default
	spec->type = FORMAT_TYPE_NONE;

	for(; *fmt; ++fmt) {
		if(*fmt == '%')
			break;
	}

	//return the current non-format string
	if(fmt != start || !*fmt)
		return fmt -start;

	//process flags
	spec->flags = 0;
	while(1) {   //maybe there are multiple flags
		bool found = true;

		++fmt;   //also skip the first %

		switch(*fmt) {
			case '-': spec->flags |= LEFT;	break;
			case '+': spec->flags |= PLUS;	break;
			case ' ': spec->flags |= SPACE; break;
			case '#': spec->flags |= SPECIAL;	break;
			case '0': spec->flags |= ZEROPAD;	break;
			default: found = false;
		}

		if(!found)        //no more flags
			break;
	}

	//get field width
	spec->field_width = -1;
	if(isdigit(*fmt))
		spec->field_width = skip_atoi(&fmt);
	else if(*fmt == '*') {
		//read the width from next argument
		spec->type = FORMAT_TYPE_WIDTH;
		return ++fmt - start;
	}

precision:
	//get the precision
	spec->precision = -1;
	if(*fmt == '.') {
		++fmt;
		if(isdigit(*fmt)) {
			spec->precision = skip_atoi(&fmt);
			if(spec->precision < 0)
				spec->precision = 0;
		}else if(*fmt == '*') {
			//read the precision from next argument
			spec->type = FORMAT_TYPE_PRECISION;
			return ++fmt - start;
		}
	}

qualifier:
	//get the qualifier
	spec->qualifier = -1;
	if(*fmt == 'h' || _tolower(*fmt) == 'l' ||
		_tolower(*fmt) == 'z' || *fmt == 't') {
		spec->qualifier = *fmt++;
		if(unlikely(spec->qualifier == *fmt)) {
			if(spec->qualifier == 'l') {
				spec->qualifier = 'L';
				++fmt;
			} else if (spec->qualifier == 'h') {
				spec->qualifier = 'H';
				++fmt;
			}
		}
	}

	//default base
	spec->base = 10;
	switch(*fmt) {
	case 'c':
		spec->type = FORMAT_TYPE_CHAR;
		return ++fmt - start;

	case 's':
		spec->type = FORMAT_TYPE_STR;
		return ++fmt - start;

	//not implemented yet
	//case 'p':
		//spec->type = FORMAT_TYPE_PTR;
		//return fmt -start;
		//skip alnum ??
	case 'n':
		spec->type = FORMAT_TYPE_NRCHARS;
		return ++fmt - start;

	case '%':
		spec->type = FORMAT_TYPE_PERCENT_CHAR;
		return ++fmt - start;

	//integer number formats - set up the flags and "break"
	case 'o':
		spec->base = 8;
		break;

	case 'x':
		spec->flags |= SMALL;

	case 'X':
		spec->base = 16;
		break;

	case 'd':
	case 'i':
		spec->flags |= SIGN;

	case 'u':
		break;

	default:
		spec->type = FORMAT_TYPE_INVALID;
		return fmt - start;
	}

	if(spec->qualifier == 'L')
		spec->type = FORMAT_TYPE_LONG_LONG;
	else if(spec->qualifier == 'l') {
		if(spec->flags & SIGN)
			spec->type = FORMAT_TYPE_LONG;
		else 
			spec->type = FORMAT_TYPE_ULONG;
	}else if(_tolower(spec->qualifier) == 'z') {
		spec->type = FORMAT_TYPE_SIZE_T;
	}else if(spec->qualifier == 't') {
		spec->type = FORMAT_TYPE_PTRDIFF;
	}else if(spec->qualifier == 'H') {
		if(spec->flags & SIGN)
			spec->type = FORMAT_TYPE_BYTE;
		else 
			spec->type = FORMAT_TYPE_UBYTE;
	}else if(spec->qualifier == 'h') {
		if(spec->flags & SIGN)
			spec->type = FORMAT_TYPE_SHORT;
		else 
			spec->type = FORMAT_TYPE_USHORT;
	} else {
		if(spec->flags & SIGN)
			spec->type = FORMAT_TYPE_INT;
		else 
			spec->type = FORMAT_TYPE_UINT;
	}

	return ++fmt - start;
}


/* print the message into the destinated struct vcpu_quantum's list */
static int __print_record(struct vcpu_quantum *vq, const char* fmt, va_list args)
{
	unsigned long long num;
	struct printf_spec spec = {0};
	int i, length = 0;

	/*
	str = &logger_dev.str;
	end = &logger_dev.end;
	*/

	//print the timestamp at the front of every message
	if(logger_dev.print_time) {
		char tbuf[50];
		unsigned long long t;
		unsigned tlen;
		unsigned long nanosec_rem;

		t = local_clock();
		nanosec_rem = do_div(t, 1000000000);
		tlen = sprintf(tbuf, "[%5lu.%06lu] ", (unsigned long)t, nanosec_rem / 1000);

		for(i = 0; i < tlen; ++i) {
			if(unlikely(vq->str >= vq->end)) 
				if(unlikely(logger_alloc_move_page(vq)))
					return length;
			*(vq->str) = tbuf[i];
			++(vq->str);
			++length;
		}
	}

	while(*fmt) {
		const char *old_fmt = fmt;
		int read = format_decode(fmt, &spec);

		fmt += read;

		switch(spec.type) {
			case FORMAT_TYPE_NONE: {
				int copy = read;
				if(unlikely(vq->str >= vq->end)) 
					if(unlikely(logger_alloc_move_page(vq)))
						return length;

				i = 0;
				while(copy - i > vq->end - vq->str) {
					memcpy(vq->str, old_fmt + i, vq->end - vq->str);
					i += (vq->end - vq->str);
					if(unlikely(logger_alloc_move_page(vq)))
						return length;
				}

				memcpy(vq->str, old_fmt + i, copy - i);

				vq->str += (copy - i);
				length += read;
				break;
			}

			case FORMAT_TYPE_WIDTH: 
				spec.field_width = va_arg(args, int);
				break;

			case FORMAT_TYPE_PRECISION:
				spec.precision = va_arg(args, int);
				break;

			case FORMAT_TYPE_CHAR: {
				char c;

				//right align
				if(!(spec.flags & LEFT)) {
					//space padding
					while(--spec.field_width > 0) {
						if(unlikely(vq->str >= vq->end)) 
							if(unlikely(logger_alloc_move_page(vq)))
								return length;
						*(vq->str) = ' ';
						++(vq->str);
						++length;
					}
				}

				c = (unsigned char) va_arg(args, int);
				if(unlikely(vq->str >= vq->end)) 
					if(unlikely(logger_alloc_move_page(vq)))
						return length;
				*(vq->str) = c;
				++(vq->str);
				++length;

				//left align
				while(--spec.field_width > 0) {
					if(unlikely(vq->str >= vq->end)) 
						if(unlikely(logger_alloc_move_page(vq)))
							return length;
					*(vq->str) = ' ';
					++(vq->str);
					++length;
				}
				break;
			}

			case FORMAT_TYPE_STR:
				i = string(vq, va_arg(args, char* ),spec);
				length += i;
				break;


			/** not implemented yet
			case FORMAT_TYPE_PTR:
				str = pointer(fmt+1, str, end, va_arg(args, void *),
					spec);
				while(isalum(*fmt))
					fmt++;
				break;
			**/

			case FORMAT_TYPE_PERCENT_CHAR:
				if(unlikely(vq->str >= vq->end)) 
					if(unlikely(logger_alloc_move_page(vq)))
						return length;
				*(vq->str) = '%';
				++(vq->str);
				++length;
				break;

			case FORMAT_TYPE_INVALID:
				if(unlikely(vq->str >= vq->end)) 
					if(unlikely(logger_alloc_move_page(vq)))
						return length;
				*(vq->str) = '%';
				++(vq->str);
				++length;
				break;

			//write the length of the output to the argument
			case FORMAT_TYPE_NRCHARS: {
				u8 qualifier = spec.qualifier;

				if(qualifier == 'l') {
					long *ip = va_arg(args, long*);
					*ip = length;
				} else if (_tolower(qualifier) == 'z') {
					size_t *ip = va_arg(args, size_t *);
					*ip = length;
				} else {
					int *ip = va_arg(args, int *);
					*ip = length;
				}
				break;
			}

			default:
				switch(spec.type) {
					case FORMAT_TYPE_LONG_LONG:
						num = va_arg(args, long long);
						break;

					case FORMAT_TYPE_ULONG:
						num = va_arg(args, unsigned long);
						break;

					case FORMAT_TYPE_LONG:
					 	num = va_arg(args, long );
					 	break;

					 case FORMAT_TYPE_SIZE_T:
					 	if(spec.flags & SIGN)
					 		num = va_arg(args, ssize_t);
					 	else
					 		num = va_arg(args, size_t);
					 	break;

					case FORMAT_TYPE_PTRDIFF:
						num = va_arg(args, ptrdiff_t);
						break;

					case FORMAT_TYPE_UBYTE:
						num = (unsigned char) va_arg(args, int);
						break;

					case FORMAT_TYPE_BYTE:
						num = (signed char) va_arg(args, int);
						break;

					case FORMAT_TYPE_USHORT:
						num = (unsigned short) va_arg(args, int);
						break;

					case FORMAT_TYPE_SHORT:
						num = (short) va_arg(args, int);
						break;

					case FORMAT_TYPE_INT:
						num = (int) va_arg(args, int);
						break;

					default:
						num = va_arg(args, unsigned int);
				}
				i = number(vq, num, spec);
				length += i;
		}
	}


	if(vq->str < vq->end)
		*(vq->str) = '\0';

	//the trailing null byte doesn't count towards the total
	return length;
}


/*this function should be removed */
int print_record(const char *fmt, ...)
{
	return 0;
}
EXPORT_SYMBOL_GPL(print_record);


int print_record_id(int vcpu_id, const char *fmt, ...)
{
	va_list args;  
	int r; 

	if(unlikely(logger_dev.state != NORMAL))
		return 0;

	va_start(args, fmt);

	r = __print_record(&logger_dev.quantums[vcpu_id], fmt, args);

	va_end(args);
	return r;   
}
EXPORT_SYMBOL_GPL(print_record_id);

module_init(logger_init);
module_exit(logger_cleanup);
