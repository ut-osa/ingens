#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/tty.h>      
#include <linux/console.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/rmap.h>
#include <asm/mman.h>
#include <linux/huge_mm.h>
#include <asm/current.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <osa/osa.h>
//#include "common.h"
#include "../fs/proc/internal.h" /* included from fs/proc/, check EXTRA_CFLAGS in Makefile */

DEFINE_SPINLOCK(osa_hpage_list_lock);

struct hpage_proc_private 
{
	struct inode *inode;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *tail_vma;
	//struct mempolicy *task_mempolicy;
};

static inline int is_vm_hugetlb_page(struct vm_area_struct *vma)
{
	return !!(vma->vm_flags & VM_HUGETLB);
}
/* ------------------------------------------- */

static int osa_hpage_pmd_entry(pmd_t *pmd, unsigned long addr, 
		unsigned long end, struct mm_walk *walk)
{
	struct seq_file *m;
	m = (struct seq_file *)walk->private;

	if (pmd_trans_huge(*pmd)) {
		seq_printf(m, "%lx - %lx: %llx\n", 
				addr, end, (pmd_val(*pmd) & __PHYSICAL_MASK) >> PAGE_SHIFT);
	}

	return 0;
}

static struct vm_area_struct * osa_hpage_next_vma(
		struct hpage_proc_private *priv, struct vm_area_struct *vma)
{
	if (vma == priv->tail_vma)
		return NULL;
	return vma->vm_next ?: priv->tail_vma;
}

static void osa_hpage_cache_vma(struct seq_file *m, struct vm_area_struct *vma)
{
	if (m->count < m->size) /* vma is copied successfully */
		m->version = osa_hpage_next_vma(m->private, vma) ? vma->vm_start : -1UL;
}

int osa_hpage_show(struct seq_file *m, void *v) 
{
	struct vm_area_struct *vma = v;
	struct mm_walk _hpage_walker = {
		.pmd_entry = osa_hpage_pmd_entry,
		.mm = vma->vm_mm,
		.private = m,
	};

	//seq_printf(m, "%lx - %lx\n", vma->vm_start, vma->vm_end);

	if (vma->vm_mm && !is_vm_hugetlb_page(vma)) {
		walk_page_range(vma->vm_start, vma->vm_end, &_hpage_walker);
		return 0;
	}

	osa_hpage_cache_vma(m, vma);
	return 0;
}

static void osa_hpage_vma_stop(struct hpage_proc_private *priv)
{
	struct mm_struct *mm = priv->mm;

	//release_task_mempolicy(priv);
	up_read(&mm->mmap_sem);
	mmput(mm);
}

static void *_seq_start(struct seq_file *m, loff_t *ppos)
{
	struct hpage_proc_private *priv = m->private;
	unsigned long last_addr = m->version;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned int pos = *ppos;

	/* See m_cache_vma(). Zero at the start or after lseek. */
	if (last_addr == -1UL)
		return NULL;

	priv->task = get_proc_task(priv->inode);
	if (!priv->task)
		return ERR_PTR(-ESRCH);

	mm = priv->mm;
	if (!mm || !atomic_inc_not_zero(&mm->mm_users))
		return NULL;

	down_read(&mm->mmap_sem);
	//hold_task_mempolicy(priv);
	priv->tail_vma = get_gate_vma(mm);

	if (last_addr) {
		vma = find_vma(mm, last_addr);
		if (vma && (vma = osa_hpage_next_vma(priv, vma)))
			return vma;
	}

	m->version = 0;
	if (pos < mm->map_count) {
		for (vma = mm->mmap; pos; pos--) {
			m->version = vma->vm_start;
			vma = vma->vm_next;
		}
		return vma;
	}

	/* we do not bother to update m->version in this case */
	if (pos == mm->map_count && priv->tail_vma)
		return priv->tail_vma;

	osa_hpage_vma_stop(priv);

	return NULL;
}
static void *_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct hpage_proc_private *priv = m->private;
	struct vm_area_struct *next;

	(*pos)++;
	next = osa_hpage_next_vma(priv, v);
	if (!next)
		osa_hpage_vma_stop(priv);
	return next;
}

static void _seq_stop(struct seq_file *m, void *v)
{
	struct hpage_proc_private *priv = m->private;

	if (!IS_ERR_OR_NULL(v))
		osa_hpage_vma_stop(priv);
	if (priv->task) {
		put_task_struct(priv->task);
		priv->task = NULL;
	}
}

static const struct seq_operations osa_hpage_seq_ops = {
	.start = _seq_start,
	.next = _seq_next,
	.stop = _seq_stop,
	.show = osa_hpage_show
};

static int osa_hpage_proc_open(struct inode *inode, struct file *file) 
{
	int err = 0;
	struct hpage_proc_private *hpage_priv;
	
	hpage_priv = __seq_open_private(file, &osa_hpage_seq_ops,
			sizeof(struct hpage_proc_private));

	if (!hpage_priv)
		return -ENOMEM;
	
	hpage_priv->inode = inode;
	hpage_priv->task = get_proc_task(inode); /* requires internal.h */

	if (!hpage_priv->task) {
		err = -ESRCH;
		seq_release_private(inode, file);
		goto out;
	}

#define PTRACE_MODE_READ 0x01
	//hpage_priv->mm = mm_access(hpage_priv->task, PTRACE_MODE_READ);
	hpage_priv->mm = get_task_mm(hpage_priv->task);

	if (IS_ERR_OR_NULL(hpage_priv->mm)) {
		err = PTR_ERR(hpage_priv->mm);
		seq_release_private(inode, file);
		goto out;
	} 

out:
	if (hpage_priv->task)
		put_task_struct(hpage_priv->task);

	return err;
}

static int osa_hpage_proc_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct hpage_proc_private *priv = seq->private;

	if (priv->mm)
		mmput(priv->mm);

	return seq_release_private(inode, file);
}

struct file_operations osa_hpage_proc_operations = {
	.owner = THIS_MODULE,
	.open = osa_hpage_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = osa_hpage_proc_release,
};

////////////////////////////////////////////////////////////////////////
static ssize_t osa_hpage_madvise_proc_write(struct file *file, 
		const char __user *buf, size_t len, loff_t *ppos)
{
	char write_buf[1];
	struct task_struct *tsk = NULL;
	struct vm_area_struct *vma, *prev = NULL;
	struct mm_struct *mm;
	int is_add = 0, rc = 0;
	unsigned long flags;

	copy_from_user(write_buf, buf, sizeof(char) * 1);

	if (write_buf[0] == '0') {
		is_add = 0;
	}
	else if(write_buf[0] == '1') {
		is_add = 1;
	}
	else
		return -EINVAL;

	if (!file->f_path.dentry->d_inode)
		return -ESRCH;

	tsk = get_proc_task(file->f_path.dentry->d_inode);
	if (!tsk)
		return -ESRCH;

	mm = get_task_mm(tsk);

	vma = mm->mmap;

	vma = find_vma_prev(mm, vma->vm_start, &prev);

	while(vma != NULL) {
		flags = vma->vm_flags;
		if (is_add) {
			rc = madvise_vma(vma, &prev, vma->vm_start, 
					vma->vm_end, MADV_HUGEPAGE);
			// for debugging
			/*
			madvise_vma(vma, &prev, vma->vm_start, 
					vma->vm_end, MADV_MERGEABLE);
			*/
		} 
		else {
			rc = madvise_vma(vma, &prev, vma->vm_start, 
					vma->vm_end, MADV_NOHUGEPAGE);
			/*
			madvise_vma(vma, &prev, vma->vm_start, 
					vma->vm_end, MADV_UNMERGEABLE);
			*/
		}

		if (rc) 
			trace_printk("error to add vma %d\n", rc);

		vma = vma->vm_next;
	}

	mmput(mm);
	put_task_struct(tsk);

	return len;
}

static int osa_hpage_madvise_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "do nothing\n");
	return 0;
}

static int osa_hpage_madvise_proc_open(struct inode *inode, struct file *file) 
{
	return single_open(file, osa_hpage_madvise_proc_show, inode);
}

static int osa_hpage_madvise_proc_release(struct inode *inode, struct file *file)
{
	return single_release(inode, file);
}

struct file_operations osa_hpage_madvise_operations = {
	.owner = THIS_MODULE,
	.open = osa_hpage_madvise_proc_open,
	.read = seq_read,
	.write = osa_hpage_madvise_proc_write,
	.release = osa_hpage_madvise_proc_release,
};

////////////////////////////////////////////////////////////////////////
static int osa_hpage_stats_proc_show(struct seq_file *m, void *v)
{
	struct file *file;
	struct task_struct *tsk = NULL;
	struct mm_struct *mm = NULL;
	unsigned int total_hpage_count = 1;

	if (!m->private)
		return -ESRCH;

	file = (struct file *)m->private;

	tsk = get_proc_task(file->f_path.dentry->d_inode);
	if (!tsk)
		return -ESRCH;

	mm = get_task_mm(tsk);

	total_hpage_count = mm->hpage_stats.total_hpage_count;
	if (total_hpage_count == 0)
		total_hpage_count++;

	seq_printf(m, "W = %u, total_hpage_count = %u, idle_hpage_count = %u, "
			"hpage_requirement = %u -- ", 
			mm->hpage_stats.weight,
			mm->hpage_stats.total_hpage_count,
			mm->hpage_stats.idle_hpage_count,
			mm->hpage_stats.hpage_requirement);

	seq_printf(m, "M_fairness = %u\n", osa_compute_fairness_metric(mm));

	mmput(mm);

	put_task_struct(tsk);

	return 0;
}

static ssize_t osa_hpage_stats_proc_write(struct file *file, 
		const char __user *buf, size_t len, loff_t *ppos)
{
	char write_buf[4];
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct inode *inode;
	unsigned int weight;
	int err;

	/* TODO: write to proc interface via 'echo' contains garbage 
	 * character. Move this to sysfs interface */
	memset(write_buf, 0, 4);
	/* only allows 4 digits */
	copy_from_user(write_buf, buf, sizeof(char) * 4);
	write_buf[3] = '\0';

	err = kstrtou32(write_buf, 4, &weight);
	if (err)
		return err;

	inode = file->f_path.dentry->d_inode;
	if (!inode)
		return -ESRCH;

	tsk = get_proc_task(inode);
	if (!tsk)
		return -ESRCH;

	mm = get_task_mm(tsk);

	/* this interface must not applied to kthread */
	if (!mm)
		goto exit;

	if (!is_member_of_scan_list(mm))
		list_add(&mm->osa_hpage_scan_link, &osa_hpage_scan_list);

	mm->hpage_stats.weight = weight;

	mmput(mm);
exit:
	put_task_struct(tsk);
	return len;
}

static int osa_hpage_stats_proc_open(struct inode *inode, struct file *file) 
{
	return single_open(file, osa_hpage_stats_proc_show, file);
}

static int osa_hpage_stats_proc_release(struct inode *inode, struct file *file)
{
	return single_release(inode, file);
}

struct file_operations osa_hpage_stats_operations = {
	.owner = THIS_MODULE,
	.open = osa_hpage_stats_proc_open,
	.read = seq_read,
	.write = osa_hpage_stats_proc_write,
	.release = osa_hpage_stats_proc_release,
};

////////////////////////////////////////////////////////////////////////

#define osa_lru_to_page(_head) (list_entry((_head), struct page, lru))

struct osa_dump_lru_private
{
	struct zonelist *_zonelist;
	struct zone *zone;
};

static void dump_lru_show_print(struct seq_file *m, pg_data_t *pgdat,
							struct zone *zone)
{
	struct list_head *head, *tmp, *iter;
	struct page *page;
	struct lruvec *lruvec;
	struct mem_cgroup *memcg;
	int i;
	struct mem_cgroup_reclaim_cookie reclaim = {
		.zone = zone,
		.priority = DEF_PRIORITY,
	};

	/* List infomation
		0 - LRU_INACTIVE_ANON = LRU_BASE,
		1 - LRU_ACTIVE_ANON = LRU_BASE + LRU_ACTIVE,
		2 - LRU_INACTIVE_FILE = LRU_BASE + LRU_FILE,
		3 - LRU_ACTIVE_FILE = LRU_BASE + LRU_FILE + LRU_ACTIVE,
		4 - LRU_UNEVICTABLE,
		5 - NR_LRU_LISTS */
	seq_printf(m, "node %d, zone %8s\n", pgdat->node_id, zone->name);
	for (i = 0; i < NR_LRU_LISTS; i++) {

		if (i >= LRU_INACTIVE_FILE)
			continue;

		seq_printf(m, "list number %d\n", i);

		memcg = mem_cgroup_iter(NULL, NULL, &reclaim);
		do {

			seq_printf(m, "cgroup id %d\n", memcg->css.cgroup->id);
			lruvec = mem_cgroup_zone_lruvec(zone, memcg);
			head = &lruvec->lists[i];
			/* from tail to head 
			list_for_each_prev_safe(iter, tmp, head) {
			*/
			/* from head to tail */
			list_for_each_safe(iter, tmp, head) {
				page = osa_lru_to_page(iter);

				seq_printf(m, "owner %d pfn %lx\n", osa_inst_get_page_owner(page, 0),
						page_to_pfn(page));
			}
		} while((memcg = mem_cgroup_iter(NULL, memcg, &reclaim)));
	}
	
}

/* Walk all the zones in a node and print using a callback */
static void osa_walk_zones_in_node(struct seq_file *m, pg_data_t *pgdat,
		void (*print)(struct seq_file *m, pg_data_t *, struct zone *))
{
	struct zone *zone;
	struct zone *node_zones = pgdat->node_zones;
	unsigned long flags;

	for (zone = node_zones; zone - node_zones < MAX_NR_ZONES; ++zone) {
		if (!populated_zone(zone))
			continue;

		spin_lock_irqsave(&zone->lock, flags);
		print(m, pgdat, zone);
		spin_unlock_irqrestore(&zone->lock, flags);
	}
}

int osa_dump_lru_show(struct seq_file *m, void *v) 
{
	pg_data_t *pgdat = (pg_data_t *)v;
	osa_walk_zones_in_node(m, pgdat, dump_lru_show_print);
	return 0;
}

static void *_dump_lru_seq_start(struct seq_file *m, loff_t *pos)
{
	pg_data_t *pgdat;
	loff_t node = *pos;

	for (pgdat = first_online_pgdat();
			pgdat && node;
			pgdat = next_online_pgdat(pgdat))
		--node;

	return pgdat;
}

static void *_dump_lru_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	pg_data_t *pgdat = (pg_data_t *)v;

	(*pos)++;

	return next_online_pgdat(pgdat);
}

static void _dump_lru_seq_stop(struct seq_file *m, void *v)
{
}

static const struct seq_operations osa_dump_lru_seq_ops = {
	.start = _dump_lru_seq_start,
	.next = _dump_lru_seq_next,
	.stop = _dump_lru_seq_stop,
	.show = osa_dump_lru_show
};

static int osa_dump_lru_proc_open(struct inode *inode, struct file *file) 
{
	int err = 0;
	struct osa_dump_lru_private *dump_lru_private;
	//struct task_struct *tsk;

	dump_lru_private = __seq_open_private(file, &osa_dump_lru_seq_ops,
			sizeof(struct osa_dump_lru_private));

	if (!dump_lru_private)
		return -ENOMEM;

	/*
	tsk = get_proc_task(inode);

	if (!tsk) {
		seq_release_private(inode, file);
		err = -ESRCH;
		goto out;
	}
	*/

	/* NUMA is not supported, only works for nid 0 now */
	dump_lru_private->_zonelist = node_zonelist(0, GFP_KERNEL);
	
	/*
out:
	if (!tsk)
		put_task_struct(tsk);
	*/

	return err;
}

static int osa_dump_lru_proc_release(struct inode *inode, struct file *file)
{
	return seq_release_private(inode, file);
}

struct file_operations osa_dump_lru_operations = {
	.owner = THIS_MODULE,
	.open = osa_dump_lru_proc_open,
	.read = seq_read,
	.release = osa_dump_lru_proc_release,
};

static int __init osa_hugepage_proc_init(void)
{
	/* init procfs */
	proc_create("dump_lru", 0, NULL, &osa_dump_lru_operations);

	return 0;
}
subsys_initcall(osa_hugepage_proc_init);

