#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <osa/osa.h>

static int osa_hpage_pmd_walker(pmd_t *pmd, unsigned long addr,
		unsigned long end, struct mm_walk *walk)
{
	unsigned long *hpage_count;
	hpage_count = (unsigned long *)walk->private;

	if (pmd_trans_huge(*pmd)) {
		(*hpage_count)++;
	}
	return 0;
}

unsigned long osa_get_hpage_count(struct mm_struct *mm)
{
	unsigned long hpage_count = 0;
	struct vm_area_struct *vma = NULL;
	struct mm_walk _hpage_walker = {
		.pmd_entry = osa_hpage_pmd_walker,
		.private = &hpage_count,
	};

	//task = find_task_by_vpid(pid);
	//mm = get_task_mm(task);

	vma = mm->mmap;
	_hpage_walker.mm = vma->vm_mm;

	while (vma != NULL) {
		if (vma->vm_mm) 
			walk_page_range(vma->vm_start, vma->vm_end, &_hpage_walker);

		vma = vma->vm_next;
	}

	return hpage_count;
}

///////////////////////////////////////////////////////////////////////////
#define DEVICE_NAME "osa_dev"
#define CLASS_NAME "osa"
#define OSA_BLOCK_SIZE (16 << 10)

static struct class*  osa_char_class  = NULL; 
static struct device* osa_char_device = NULL; 
static int majorNumber;
static int is_allocated = 0;
static char **osa_dev_mem = NULL;
static unsigned int nr_mem_block = ((350 << 20) / OSA_BLOCK_SIZE);

static ssize_t osa_dev_read(struct file *filep, char *buffer, 
		size_t len, loff_t *offset)
{
	return 0;
}

static ssize_t osa_dev_write(struct file *filep, const char *buffer, 
		size_t len, loff_t *offset)
{
	char message[16] = {0};  
	unsigned long flag;
	unsigned int i;

	if (copy_from_user(message, buffer, 16)) 
		return -EFAULT;

	flag = simple_strtoul(message, NULL, 10);

	switch (flag) {
		case 0:
			if (is_allocated) {
				for (i = 0; i < nr_mem_block; i++) 
					kfree(osa_dev_mem[i]);
			}
			is_allocated = 0;
			break;
		case 1:
			if (!is_allocated) {
				for (i = 0; i < nr_mem_block; i++)  {
					osa_dev_mem[i] = kmalloc(OSA_BLOCK_SIZE, GFP_KERNEL);
					if (!osa_dev_mem[i])
						printk("osa_dev: fail to alloc %dth block\n", i);
				}

			}
			is_allocated = 1;
			break;
		default:
			printk("osa_dev: Invalid command %lu\n", flag);
	}

	return len;
}

static int osa_dev_open(struct inode *inodep, struct file *filep)
{
	return 0;
}

static int osa_dev_release(struct inode *inodep, struct file *filep)
{
	return 0;
}

static struct file_operations fops =
{
	.open = osa_dev_open,
	.read = osa_dev_read,
	.write = osa_dev_write,
	.release = osa_dev_release,
};

static int __init osa_alloc_unmovable_memory(void)
{
	majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
	if (majorNumber<0){
		printk(KERN_ALERT "failed to register a major number\n");
		return majorNumber;
	}

	printk(KERN_INFO "osa_dev: registered correctly with major number %d\n",
			majorNumber);

	// Register the device class
	osa_char_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(osa_char_class)) { 
		unregister_chrdev(majorNumber, DEVICE_NAME);
		printk(KERN_ALERT "Failed to register device class\n");
		return PTR_ERR(osa_char_class); 
	}
	printk(KERN_INFO "osa_dev: device class registered correctly\n");

	// Register the device driver
	osa_char_device = device_create(osa_char_class, 
			NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
	if (IS_ERR(osa_char_device)){      
		class_destroy(osa_char_class);   
		unregister_chrdev(majorNumber, DEVICE_NAME);
		printk(KERN_ALERT "Failed to create the device\n");
		return PTR_ERR(osa_char_device);
	}
	printk(KERN_INFO "osa_char: device class created correctly\n");

	osa_dev_mem = kmalloc(sizeof(char *) * nr_mem_block, GFP_KERNEL);

	return 0;
}

subsys_initcall(osa_alloc_unmovable_memory);
