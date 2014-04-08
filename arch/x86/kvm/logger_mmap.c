/*
* mmap.c  -- memory mapping for the logger module
*/
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <asm/pgtable.h>
#include <linux/fs.h>

#include <linux/slab.h>

#include "logger.h"


extern struct kmem_cache *data_cache;
extern struct kmem_cache *quantum_cache;
extern int logger_quantum;

/*
*open and close: keep track of how many times the device is mapped
* maybe will do some cleanup
*/

void logger_vma_open(struct vm_area_struct *vma)
{
	struct logger_dev *dev = vma->vm_private_data;

	spin_lock(&dev->dev_lock);
	++(dev->vmas);
	spin_unlock(&dev->dev_lock);
}

void logger_vma_close(struct vm_area_struct *vma)
{
	struct logger_dev *dev = vma->vm_private_data;
	struct logger_quantum *ptr;

	spin_lock(&dev->dev_lock);
	--(dev->vmas);
	/* delete the data has been mapped before */
	if(likely(dev->vmas == 0 && dev->head)) {
		ptr = dev->head;
		if(ptr->next) {
			dev->head = ptr->next;
		}else {
			dev->head = dev->tail = NULL;
		}
		kmem_cache_free(data_cache, ptr->data);
		kmem_cache_free(quantum_cache, ptr);
	}
	spin_unlock(&dev->dev_lock);
}



struct vm_operations_struct logger_vm_ops = {
	.open = logger_vma_open,
	.close = logger_vma_close,
};


int logger_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct logger_dev *dev = (struct logger_dev *)filp->private_data;
	struct logger_quantum *ptr;
	int retval = 0;
	struct page *page;
	void *pageptr = NULL;
	unsigned long offset;

	vma->vm_ops = &logger_vm_ops;
	vma->vm_flags = VM_LOCKED;
	vma->vm_private_data = filp->private_data;

	spin_lock(&dev->dev_lock);

	if(unlikely(!dev->head)) {
		/* there is nothing in the out_list
		 * the user-space should not mmap() the device now
		 */
		retval = -EPERM;
		goto err;
	}
	
	offset = vma->vm_pgoff;
	for(ptr = dev->head; ptr && offset;) {
		ptr = ptr->next;
		--offset;
	}

	if(ptr) {
		pageptr = ptr->data;
	}
	if(!pageptr) {
		retval = -ENODEV;
		goto err;      /* end of file */
	}
	page = virt_to_page(pageptr);

	if(remap_pfn_range(vma, vma->vm_start,
		page_to_pfn(page), logger_quantum, vma->vm_page_prot)) {
		pr_err("Err: fail to remap_pfn_range() for logger\n");
		retval = -ENXIO;
		goto err;
	}

	spin_unlock(&dev->dev_lock);
	logger_vma_open(vma);

	return retval;

err:
	spin_unlock(&dev->dev_lock);
	return retval;
}
