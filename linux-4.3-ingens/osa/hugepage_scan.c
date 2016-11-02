#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/console.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/bootmem.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/mm_inline.h>
#include <linux/huge_mm.h>
#include <linux/page_idle.h>
#include <linux/ksm.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/freezer.h>
#include <linux/compaction.h>
#include <linux/mmzone.h>
#include <linux/node.h>
#include <linux/workqueue.h>
#include <linux/khugepaged.h>
#include <linux/hugetlb.h>
#include <linux/migrate.h>
#include <linux/balloon_compaction.h>
#include <linux/pagevec.h>
#include <linux/random.h>
#include <asm/uaccess.h>
#include <asm/current.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <osa/osa.h>
#include "../../../fs/proc/internal.h" 
#include "../mm/internal.h"

#define SCAND_WQ 

#define SEC_SCAN_COUNT 0x8

unsigned int hugepage_fairness = 0;
unsigned long distance_divisor = 0;
unsigned long active_bpage_count = 0;

DEFINE_SPINLOCK(osa_page_set_lock);
DEFINE_SPINLOCK(osa_poplmap_lock);
DECLARE_WAIT_QUEUE_HEAD(osa_hpage_scand_wait);
DECLARE_WAIT_QUEUE_HEAD(osa_hpage_compactd_wait);
DECLARE_WAIT_QUEUE_HEAD(osa_aggregationd_wait);
struct list_head osa_aggregation_list;

#ifdef SCAND_WQ
static struct workqueue_struct *osa_hpage_scand_wq __read_mostly;
static struct work_struct osa_hpage_scan_work;
static struct task_struct *osa_aggregation_kthread __read_mostly;
#else
static struct task_struct *osa_hpage_scand_kthread __read_mostly;
#endif
static struct task_struct *osa_hpage_compactd_kthread __read_mostly;
static unsigned int scan_sleep_millisecs = 4000;
static unsigned int aggregation_sleep_millisecs = 0;
static unsigned int compact_sleep_millisecs =  0;
static unsigned long free_contig_pages_consumed;
/* In a scanning of inactive list, this variable indicates
 * how many scanning can be passed for huge page */
unsigned int deferred_mode = 1;
unsigned int util_threshold = 90;
struct list_head hugepage_worklist;
static util_node_t *_util_node[512];

static struct list_head osa_hot_page_set[5];
static unsigned int freq_scan_count = 0;
static unsigned int osa_aggr_scan_count = 0;
static unsigned long count[5];

struct osa_walker_stats {
	unsigned int hpage_requirement;
	unsigned int total_hpage_count;
	unsigned long total_bpage_count;
	unsigned int idle_hpage_count;
	unsigned long idle_bpage_count;
	unsigned int idle_tau; //idle page penalty parameter
	unsigned int weight;
	//up-to-here it is the same as osa_hpage_stats
	//so casting to osa_hpage_stat is safe.
	unsigned int hit;
	unsigned int miss;
	unsigned long nopromote;
};

int is_member_of_scan_list(struct mm_struct *mm)
{
	struct list_head *pos, *tmp;
	struct mm_struct *m = NULL;

	list_for_each_safe(pos, tmp, &osa_hpage_scan_list) {
		m = list_entry(pos, struct mm_struct, osa_hpage_scan_link);

		if (m && m == mm)
			return 1;
	}

	return 0;
}

unsigned int osa_compute_fairness_metric(struct mm_struct *mm) 
{
	unsigned int fairness_metric, total_hpage_count;

	if (mm->hpage_stats.total_hpage_count == 0)
		total_hpage_count = 1;
	else
		total_hpage_count = mm->hpage_stats.total_hpage_count;

	fairness_metric = (mm->hpage_stats.weight 
		* (mm->hpage_stats.hpage_requirement * 100))
		/ total_hpage_count;

	return fairness_metric;
}

void *osa_popl_node_delete(struct mm_struct *mm, unsigned long address)
{
	return radix_tree_delete(&mm->root_popl_map, PAGE_ALIGN_FLOOR(address));
}

void *osa_popl_node_lookup(struct mm_struct *mm, unsigned long address)
{
	return radix_tree_lookup(&mm->root_popl_map, PAGE_ALIGN_FLOOR(address));
}

int osa_popl_node_insert(struct mm_struct *mm,
		unsigned long address, popl_node_t *node)
{
	return radix_tree_insert(&mm->root_popl_map, 
			PAGE_ALIGN_FLOOR(address), node);
}

inline aggr_node_t *osa_aggr_node_alloc(void)
{
	aggr_node_t *aggr_node;

	aggr_node = kmem_cache_zalloc(osa_aggregate_node_cachep, GFP_ATOMIC);

	if (!aggr_node)
		return NULL;

	return aggr_node;
}

void osa_aggr_node_free(aggr_node_t *aggr_node)
{
	kmem_cache_free(osa_aggregate_node_cachep, aggr_node);
}

///////////////////////////////////////////////////////////////////
// Guest physical memory aggregation

typedef struct aggregate_control {
	struct list_head aggregate_list;
	struct list_head free_list;
	unsigned int nr_aggregate;
	unsigned int nr_free;
} aggregate_control_t;

static struct page *osa_ac_new_page(struct page *page, 
		unsigned long private, int **unused) 
{
	aggregate_control_t *ac;
	struct page *freepage;

	ac = (aggregate_control_t *)private;

	if (list_empty(&ac->free_list)) {
		trace_printk("Something Wrong\n");
		return NULL;
	}

	freepage = list_entry(ac->free_list.next, struct page, lru);
	/*
	trace_printk("alloc page %lx mapcount %d count %d\n", 
			page_to_pfn(freepage), 
			atomic_read(&freepage->_mapcount),
			atomic_read(&freepage->_count));
	*/

	set_bit(OSA_PF_AGGR, &freepage->osa_flag);
	list_del(&freepage->lru);
	ac->nr_free--;

	return freepage;
	//return alloc_pages(GFP_HIGHUSER_MOVABLE, 0);
}

static void osa_ac_free_page(struct page *page, 
		unsigned long private)
{
	aggregate_control_t *ac;
	ac = (aggregate_control_t *)private;

	list_add_tail(&page->lru, &ac->free_list);
	ac->nr_free++;
}

static void putback_aggregate_pages(struct list_head *l)
{
	struct page *page;
	struct page *page2;

	list_for_each_entry_safe(page, page2, l, lru) {
		clear_bit(OSA_PF_AGGR, &page->osa_flag);
		list_del(&page->lru);
		dec_zone_page_state(page, NR_ISOLATED_ANON +
				page_is_file_cache(page));
		if (unlikely(isolated_balloon_page(page)))
			balloon_page_putback(page);
		else
			putback_lru_page(page);
	}
}

static int isolate_aggregate_list(aggregate_control_t *ac)
{
	struct page *page;
	struct list_head *l, *t;
	int rc;
	aggr_node_t *aggr_node;

	spin_lock(&osa_page_set_lock);

	list_for_each_safe(l, t, &osa_aggregation_list) {
		aggr_node = list_entry(l, aggr_node_t, link);
		if (!aggr_node)
			continue;

		page = aggr_node->page;

		if (unlikely(!page))
			continue;

		/* checks whether pages can be aggregated or not */
		if (page->osa_flag & OSA_PF_AGGR)
			continue;

		/* skip hugepage (transparent or hugetlb) */
		if (PageTransCompound(page))
			continue;

		if (unlikely(!PageLRU(page)))
			continue;

		/* skip VDSO */
		if (PageReserved(page))
			continue;

		/* skip zero pfn */
		if (is_zero_pfn(page_to_pfn(page)))
			continue;

		/* skip shared page */
		if (page_mapcount(page) > 1)
			continue;

		rc = isolate_lru_page(page);
		if (rc) {
			putback_lru_page(page);
			continue;
		}

		//trace_printk("isolated page %lx\n", page_to_pfn(page));

		inc_zone_page_state(page, NR_ISOLATED_ANON +
				page_is_file_cache(page));

		list_add(&page->lru, &ac->aggregate_list);
		ac->nr_aggregate++;

		list_del(&aggr_node->link);
		osa_aggr_node_free(aggr_node);

		if (ac->nr_aggregate >= 512)
			break;
	}

	spin_unlock(&osa_page_set_lock);

	return 0;
}

static int osa_gfn_aggregate(int total_nr_aggregate)
{
	int rc = 0;
	struct page *page, *_page;
	unsigned int i, j, max_page_block = 25;
	aggregate_control_t ac = {
		.nr_aggregate = 0,
		.nr_free = 0,
	};

	for (i = 0; i < max_page_block; i++) {
		ac.nr_aggregate = 0;
		ac.nr_free = 0;
		INIT_LIST_HEAD(&ac.aggregate_list);
		INIT_LIST_HEAD(&ac.free_list);

		rc = isolate_aggregate_list(&ac);

		if (ac.nr_aggregate == 512) {
			gfp_t gfp = GFP_HIGHUSER_MOVABLE;
			page = alloc_pages(gfp, HPAGE_PMD_ORDER);

			if (!page) {
				trace_printk("Fail to allocate dst page\n");
				continue;
			}

			/*
			trace_printk("Dest pfn %lx - %lx\n", 
					page_to_pfn(page), page_to_pfn(page+511));
			*/
			for (j = 0, _page = page; j < 512; j++, _page++) {
				get_page(_page);
				list_add_tail(&_page->lru, &ac.free_list);
			}

			migrate_prep();

			rc = migrate_pages(&ac.aggregate_list, 
					osa_ac_new_page, osa_ac_free_page, 
					(unsigned long)&ac,
					MIGRATE_SYNC, MR_GFN_AGGREGATE);

			/*
			trace_printk("[------] aggregate page %d (failed %d)\n", 
					ac.nr_aggregate, rc);
			*/

			// handle migration failed page
			if (rc) 
				putback_aggregate_pages(&ac.aggregate_list);

			if(ac.nr_free > 0) {
				struct page *page, *next;

				list_for_each_entry_safe(page, next, &ac.free_list, lru) {
					clear_bit(OSA_PF_AGGR, &page->osa_flag);
					list_del(&page->lru);
					putback_lru_page(page);
				}
			}

			total_nr_aggregate -= 512;
		} else {
			putback_aggregate_pages(&ac.aggregate_list);
		}

		if (total_nr_aggregate < 512)
			break;
	}

	return 0;
}

///////////////////////////////////////////////////////////////////
// osa_aggregationd

static int osa_aggregationd_has_work(void)
{
	return aggregation_sleep_millisecs && 
		!list_empty(&osa_aggregation_list);
}

static int osa_aggregationd_wait_event(void)
{
	return aggregation_sleep_millisecs && 
        (!list_empty(&osa_aggregation_list) || kthread_should_stop());
}

static void osa_aggregation_wait_work(void) 
{
	if (osa_aggregationd_has_work()) {
		wait_event_freezable_timeout(osa_aggregationd_wait,
				kthread_should_stop(),
				msecs_to_jiffies(aggregation_sleep_millisecs));
	} else
		wait_event_freezable(osa_aggregationd_wait, 
				osa_aggregationd_wait_event());

	return;
}

void osa_aggregation_do_scan(void)
{
	aggr_node_t *aggr_node, *tmp;
	unsigned long pfn;
	struct page *page, *_page;
	unsigned int nr_aggregate;
	unsigned int accessed = 0;

	list_for_each_entry_safe(aggr_node, tmp, 
			&osa_aggregation_list, link)  {
		page = aggr_node->page;

		if (!page)
			continue;

		pfn = page_to_pfn(page);

		_page = page_idle_get_page(pfn);

		if (_page) {
			VM_BUG_ON(page != _page);
			VM_BUG_ON(PageCompound(_page));

			page_idle_clear_pte_refs(_page);

			bitmap_shift_left(aggr_node->access_bitmap,
					aggr_node->access_bitmap, 1, AGGR_BITMAP_SIZE);

			if (page_is_idle(_page))  {
				bitmap_clear(aggr_node->access_bitmap, 0, 1);
			} else {
				bitmap_set(aggr_node->access_bitmap, 0, 1);
				accessed++;
			}

			set_page_idle(_page);
			put_page(_page);
		}
	}

	osa_aggr_scan_count++;

	if (osa_aggr_scan_count == AGGR_BITMAP_SIZE) {
		osa_aggr_scan_count = 0;
		nr_aggregate = 0;

		//check osa_aggregation_list
		list_for_each_entry_safe(aggr_node, tmp, 
				&osa_aggregation_list, link)  {
			if (!aggr_node)
				continue;

			page = aggr_node->page;

			BUG_ON(!page);

			if (bitmap_weight(aggr_node->access_bitmap, 
						AGGR_BITMAP_SIZE) >= 3) {
				nr_aggregate++;
			} else {
				list_del(&aggr_node->link);
				osa_aggr_node_free(aggr_node);
			}
		}

		//Perform aggregation
		if (nr_aggregate >= 512)
			osa_gfn_aggregate(nr_aggregate);

		//Cleanup osa_aggregation_list
		list_for_each_entry_safe(aggr_node, tmp, 
				&osa_aggregation_list, link)  {
			list_del(&aggr_node->link);
			osa_aggr_node_free(aggr_node);
		}

		INIT_LIST_HEAD(&osa_aggregation_list);
	}
	return;
}

static int osa_aggregationd(void *none)
{
	set_freezable();
	set_user_nice(current, MAX_NICE);

	while(!kthread_should_stop()) {
		osa_aggregation_do_scan();
		osa_aggregation_wait_work();
	}

	return 0;
}

///////////////////////////////////////////////////////////////////
// osa_aggregationd

/* I did not call get_page before returning page.
 * So caller must handle the case when page status is changed (e.g. freed)*/
static struct page *osa_follow_page(struct mm_struct *mm, unsigned long address) 
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	spinlock_t *ptl;
	struct page *page;
	unsigned long pfn;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		return NULL;

	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		return NULL;
	// 1GB hugepage
	if (pud_huge(*pud)) {
		if (pud_present(*pud)) {
			return pte_page(*(pte_t *)pud) + ((address & ~PUD_MASK) >> PAGE_SHIFT);
		} else
			return NULL;
	}

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		return NULL;
	// 2MB hugepage (hugetlb)
	if (pmd_huge(*pmd)) {
		ptl = pmd_lockptr(mm, pmd);
		spin_lock(ptl);
		if (pmd_present(*pmd)) {
			page = pmd_page(*pmd) + ((address & ~PMD_MASK) >> PAGE_SHIFT);
		} else
			page = NULL;
		spin_unlock(ptl);

		return page;
	}

	// 2MB hugepage (Transparent hugepage)
	if (pmd_trans_huge(*pmd)) {
		ptl = pmd_lockptr(mm, pmd);
		if (likely(!pmd_trans_splitting(*pmd))) {
			//Follow PMD entry. There is many corner cases 
			//(e.g., on going of NUMA migration) 
			//but I simplify the checks only necessary for our case.
			page = pmd_page(*pmd);

			// checks whether the page is compound or not
			VM_BUG_ON_PAGE(!PageHead(page), page);
		} else {
			page = NULL;
		}
		spin_unlock(ptl);

		return page;
	}

	ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
	pte = *ptep;

	if (!pte_present(pte)) {
		page = NULL;
	} else {
		pfn = pte_pfn(pte);

		if (unlikely(pfn > highest_memmap_pfn)) {
			page = NULL;
		} else {
			// did not check the case 
			// 1. where address is from the last page.
			// In that case, base_address of last page < address
			// 2. address is used for fixed map
			// For other detailed checks, refer to vm_normal_page()
			
			if (is_zero_pfn(pfn)) {
				page = NULL;
			} else {
				page = pfn_to_page(pfn);
			}
		}
	}

	pte_unmap_unlock(ptep, ptl);

	return page;
}

/* freq_node API */
//deprecated
int osa_util_node_insert(struct mm_struct *mm,
		unsigned long address, util_node_t *node)
{
	return 0;
}

//deprecated
void *osa_util_node_delete(struct mm_struct *mm, unsigned long address)
{
	return NULL;
}

void *osa_util_node_lookup(struct mm_struct *mm, unsigned long address)
{
	struct page *page = NULL;

	page = osa_follow_page(mm, PAGE_ALIGN_FLOOR(address));

	if (page)
		return (void *)&page->util_info;
	else
		return NULL;
}

void *osa_util_node_lookup_fast(struct page *page)
{
	return (void *)&page->util_info;
}

void frequency_update(util_node_t *node) 
{
    int i;

    if (!node) 
        return;

#if 0 //ARMA method.
    //may replace with bitwise operation in future
    for (i = PRI_HISTORY_SIZE - 1; i > 0; i--)
        node->frequency[i] = node->frequency[i-1];

    node->frequency[0] = (int32_t)((int32_t)((uint16_t)node->freq_bitmap[0])
        - (1<<(FREQ_BITMAP_SIZE-1)));
    //trace_printk("node priority updated: %d\n", node->frequency[0]);

    //to avoid division
    for (i = 1; i < PRI_HISTORY_SIZE; i++)
        if (node->frequency[i] >= 0)
            node->frequency[0] += node->frequency[i] >> i;
		else
            node->frequency[0] -= (-node->frequency[i]) >> i;
#else //EMA method.
	node->frequency[1] = bitmap_weight(node->freq_bitmap, FREQ_BITMAP_SIZE);
	node->frequency[1] -= (3 * FREQ_BITMAP_SIZE / 4);
	node->frequency[0] = (node->frequency[0] * 70) + (node->frequency[1] * 30);
	node->frequency[0] = node->frequency[0] / 100;
#endif
}

static int osa_bpage_pte_walker(pte_t *pte, unsigned long addr,
		unsigned long end, struct mm_walk *walk)
{
    struct page *page = NULL;
	struct osa_walker_stats *walker_stats;
	unsigned long pfn;
    util_node_t *f_node;
    struct mm_struct *mm;
	int ret = 0;
	unsigned long lottery;
	uint8_t lottery_selected = 0;

	mm = (struct mm_struct *)walk->mm;
	walker_stats = (struct osa_walker_stats *)walk->private;

    if (pte && !pte_none(*pte))
        page = pte_page(*pte);

    if (page && !PageTransCompound(page)) {
		walker_stats->total_bpage_count++;

		pfn = (pte_val(*pte) & PTE_PFN_MASK) >> PAGE_SHIFT;
		page = page_idle_get_page(pfn);

		if (page) {
			page_idle_clear_pte_refs(page);

            //f_node = osa_util_node_lookup(mm, PAGE_ALIGN_FLOOR(addr));
            f_node = osa_util_node_lookup_fast(page);
			f_node->page = page;

			if (!f_node) 
				goto out;

			bitmap_shift_right(f_node->freq_bitmap, f_node->freq_bitmap, 1,
					FREQ_BITMAP_SIZE);

			if (deferred_mode >= 2) {
				// hot page: run lottery for a random sampling.
				if (f_node->frequency[0] >= 0) {
					//get_random_bytes(&lottery, sizeof(unsigned long));
					get_random_bytes_arch(&lottery, sizeof(unsigned long));
					if (!active_bpage_count)
						active_bpage_count++;
					if (lottery % active_bpage_count > 
							((active_bpage_count * 20) / 100)) {
						lottery_selected = 1;
					} else {
						lottery_selected = 0;
						clear_page_idle(page);
					}
				} else {
					// cold page: lottery is always selected.
					lottery_selected = 1;
				}
			} else
				lottery_selected = 1;

			// Clearing access bit causes a TLB miss of the address.
			if (lottery_selected) {
				page_idle_clear_pte_refs(page);

				bitmap_shift_right(f_node->freq_bitmap, f_node->freq_bitmap, 1,
						FREQ_BITMAP_SIZE);
			}

			if (page_is_idle(page)) {
				walker_stats->idle_bpage_count++;
                bitmap_clear(f_node->freq_bitmap, FREQ_BITMAP_SIZE-1, 1);
                if (f_node->frequency[0] >= 0) {
					walker_stats->miss++;
				} else {
					walker_stats->hit++;
				}
			} else {
                bitmap_set(f_node->freq_bitmap, FREQ_BITMAP_SIZE-1, 1);
                if (f_node->frequency[0] < 0) {
					walker_stats->miss++;
				} else {
					walker_stats->hit++;
				}
			}

			frequency_update(f_node);
			set_page_idle(page);
			put_page(page);

			if ((freq_scan_count % SEC_SCAN_COUNT) == 0) {
				unsigned int weight = 0, i = 0;
				if (!spin_trylock(&osa_page_set_lock))
					goto out;

				//Clear osa_flag to enable re-aggregation
				if ((freq_scan_count & 0xff) == 0)
					clear_bit(OSA_PF_AGGR, &page->osa_flag);

				for (i = FREQ_BITMAP_SIZE - 1; i > FREQ_BITMAP_SIZE - 5; i--) 
					if (test_bit(i, f_node->freq_bitmap))
						weight++;

				if (weight == 4) {
					list_add(&f_node->link, &osa_hot_page_set[0]);
					count[0]++;
				}

				/* //used for ARMA method.
				switch(bitmap_weight(f_node->freq_bitmap, FREQ_BITMAP_SIZE)) {
					case FREQ_BITMAP_SIZE:
						list_add(&f_node->link, &osa_hot_page_set[0]);
						count[0]++;
						break;
					case FREQ_BITMAP_SIZE - 1:
						list_add(&f_node->link, &osa_hot_page_set[1]);
						count[1]++;
						break;
					case FREQ_BITMAP_SIZE - 2:
						list_add(&f_node->link, &osa_hot_page_set[2]);
						count[2]++;
						break;
					case FREQ_BITMAP_SIZE - 3:
						list_add(&f_node->link, &osa_hot_page_set[3]);
						count[3]++;
						break;
					case FREQ_BITMAP_SIZE - 4:
						list_add(&f_node->link, &osa_hot_page_set[4]);
						count[4]++;
						break;
				}
				*/

				spin_unlock(&osa_page_set_lock);
			}
		}
    }
out:
    return ret;
}

static int osa_hpage_pmd_walker(pmd_t *pmd, unsigned long addr,
		unsigned long end, struct mm_walk *walk)
{
	struct osa_walker_stats *walker_stats;
	struct page *page;
	unsigned long _addr, pfn;
    util_node_t *f_node;
	pte_t *pte;
    struct mm_struct *mm;
	int ret = 0;

	mm = (struct mm_struct *)walk->mm;
	walker_stats = (struct osa_walker_stats *)walk->private;

	if (pmd_trans_huge(*pmd)) {
		// Count total huge page
		walker_stats->total_hpage_count++;

		// Count Idle huge page
		pfn = (pmd_val(*pmd) & PTE_PFN_MASK) >> PAGE_SHIFT;
		page = page_idle_get_page(pfn);

		if (page) {
			page_idle_clear_pte_refs(page);
			//f_node = osa_util_node_lookup(mm, HPAGE_ALIGN_FLOOR(addr));

			VM_BUG_ON(!PageCompound(page));
			f_node = osa_util_node_lookup_fast(page);
			f_node->page = page;

			if (!f_node)
				goto out;

			bitmap_shift_right(f_node->freq_bitmap, f_node->freq_bitmap, 1,
					FREQ_BITMAP_SIZE);

			if (page_is_idle(page)) {
				walker_stats->idle_hpage_count++;
				bitmap_clear(f_node->freq_bitmap, FREQ_BITMAP_SIZE-1, 1);
				if (f_node->frequency[0] > 0) {
					walker_stats->miss += 512;
				} else {
					walker_stats->hit += 512;
				}
			}
			else {
				bitmap_set(f_node->freq_bitmap, FREQ_BITMAP_SIZE-1, 1);
				if (f_node->frequency[0] < 0) {
					walker_stats->miss += 512;
				} else {
					walker_stats->hit += 512;
				}
			}

			frequency_update(f_node);
			set_page_idle(page);
			put_page(page);
		}
	} else {
		// Walk PTE
		pte = pte_offset_map(pmd, addr);

		_addr = addr;

		for (;;) {
			ret = osa_bpage_pte_walker(pte, _addr, _addr + PAGE_SIZE, walk);
			if (ret)
				break;

			_addr += PAGE_SIZE;
			if (_addr == end)
				break;

			pte++;
		}
	}

#if 0  //Experimental features. currently unused.
	/* frequency based hugepage promotion */
	if (!pmd_trans_huge(*pmd) && deferred_mode >= 3) {
		struct vm_area_struct *vma;
		unsigned long haddr = HPAGE_ALIGN_FLOOR(addr);
		unsigned long _addr;
		work_node_t *work_node = NULL;
		unsigned int i, first, promote = 0;
		DECLARE_BITMAP(locality_bitmap, FREQ_BITMAP_SIZE);

		vma = find_vma(mm, addr);
		if (transparent_hugepage_enabled(vma) &&
			vma_is_anonymous(vma) &&
			!(haddr < vma->vm_start || haddr + HPAGE_PMD_SIZE > vma->vm_end) &&
			!(unlikely(khugepaged_enter(vma, vma->vm_flags))) 
		   ) {

			pfn = (pmd_val(*pmd) & PTE_PFN_MASK) >> PAGE_SHIFT;
			page = pfn_to_page(pfn);

			VM_BUG_ON(PageCompound(page));

			for (first = i = 0, _addr = haddr; _addr < haddr + HPAGE_SIZE; 
					_addr += PAGE_SIZE, i++) {
				_util_node[i] = osa_util_node_lookup(mm, _addr);
				if (!first && _util_node[i])
					first = i;

			}

			bitmap_zero(locality_bitmap, FREQ_BITMAP_SIZE);
			bitmap_or(locality_bitmap, locality_bitmap, 
					_util_node[first]->freq_bitmap, FREQ_BITMAP_SIZE);

			for (i = first ; i < 512; i++) {
				if (_util_node[i])
					bitmap_and(locality_bitmap, locality_bitmap,
							_util_node[i]->freq_bitmap, FREQ_BITMAP_SIZE);

			}

			if (bitmap_weight(locality_bitmap, FREQ_BITMAP_SIZE) 
					> (FREQ_BITMAP_SIZE * 60 / 100)) {
				/* trace_printk("ASK Promote : %lx %d\n", haddr,
				   bitmap_weight(locality_bitmap, FREQ_BITMAP_SIZE)); */
				promote = 1;
			} else {
				/* trace_printk("NO promote : %lx %d\n", haddr,
				   bitmap_weight(locality_bitmap, FREQ_BITMAP_SIZE)); */
				promote = 0;
				walker_stats->nopromote++;
			}

			if (promote) {
				/*
				trace_printk("go Promote : %lx %d\n", haddr,
						bitmap_weight(locality_bitmap, FREQ_BITMAP_SIZE)); 
				*/
				work_node = osa_work_node_alloc();
				work_node->mm = mm;
				work_node->address = haddr;

				spin_lock(&worklist_lock);
				list_add_tail(&work_node->list, 
						&hugepage_worklist);
				spin_unlock(&worklist_lock);

				wake_up_interruptible(&khugepaged_wait);
			}
		}
	}
#endif

out:
	return ret;
}

void osa_hpage_enter_list(struct mm_struct *mm)
{
	spin_lock(&osa_hpage_list_lock);
	list_add_tail_rcu(&mm->osa_hpage_scan_link, &osa_hpage_scan_list);
	spin_unlock(&osa_hpage_list_lock);
}

void osa_hpage_exit_list(struct mm_struct *mm)
{
	spin_lock(&osa_hpage_list_lock);

	VM_BUG_ON(!mm);

	list_del_rcu(&mm->osa_hpage_scan_link);

	spin_unlock(&osa_hpage_list_lock);
}

/* scanner kthread */
static int osa_hpage_do_walk(struct mm_struct *mm, 
		struct osa_walker_stats *walker_stats) 
{
	int err = 0;
	unsigned int hpage_requirement = 0;
	unsigned long haddr;
	unsigned int anon_rss;
	struct vm_area_struct *vma = NULL;
	struct mm_walk _hpage_walker = {
		.pmd_entry = osa_hpage_pmd_walker,
		.mm = mm,
		.private = walker_stats,
	};

	VM_BUG_ON(!mm);

	vma = mm->mmap;

	walker_stats->hpage_requirement = 0;
	walker_stats->miss = 0;
	walker_stats->hit = 0;
	walker_stats->nopromote = 0;

	for ( ;vma != NULL; vma = vma->vm_next) {
		if (!vma_is_anonymous(vma))
			continue;
			
		//Entire VMA scanning.
		err = walk_page_vma(vma, &_hpage_walker);

		if (err) {
			trace_printk("error in vma walk\n");
			return err;
		}

		if (transparent_hugepage_enabled(vma)) {
			for (haddr = HPAGE_ALIGN_FLOOR(vma->vm_start); haddr < vma->vm_end; 
					haddr += HPAGE_PMD_SIZE) 
				hpage_requirement++;
		}

		cond_resched();
	}

	mm->hpage_stats.total_hpage_count = walker_stats->total_hpage_count;
	mm->hpage_stats.total_bpage_count = walker_stats->total_bpage_count;
	mm->hpage_stats.idle_hpage_count = walker_stats->idle_hpage_count;
	mm->hpage_stats.idle_bpage_count = walker_stats->idle_bpage_count;

	active_bpage_count = walker_stats->total_bpage_count - 
		walker_stats->idle_bpage_count;

	anon_rss = get_mm_counter(mm, MM_ANONPAGES);
	/* hpage_requirment is represented in terms of # of huge page */
	mm->hpage_stats.hpage_requirement = anon_rss / 512;

	return 0;
}

static void osa_page_cache_scan(struct super_block *sb, void *unused)
{
	struct inode *inode, *toput_inode = NULL;
	pgoff_t indices[PAGEVEC_SIZE];
	struct pagevec pvec;
	pgoff_t index = 0, end = -1;
	struct address_space *mapping;
	util_node_t *f_node;
	int i;

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);
		if ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
		    (inode->i_mapping->nrpages < (300 << 8))) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&sb->s_inode_list_lock);

		pagevec_init(&pvec, 0);

		mapping = inode->i_mapping; 

		while (index <= end && pagevec_lookup_entries(&pvec, mapping, index,
					min(end - index, (pgoff_t)PAGEVEC_SIZE - 1) + 1,
					indices)) {
			for (i = 0; i < pagevec_count(&pvec); i++) {
				struct page *_page = pvec.pages[i];
				struct page *page;

				/* We rely upon deletion not changing page->index */
				index = indices[i];
				if (index > end)
					break;

				if (radix_tree_exceptional_entry(_page)) {
					//clear_exceptional_entry(mapping, index, page);
					continue;
				}

				page = page_idle_get_page(page_to_pfn(_page));

				if (page) {
					page_idle_clear_pte_refs(page);

					//f_node = osa_util_node_lookup(mm, PAGE_ALIGN_FLOOR(addr));
					f_node = osa_util_node_lookup_fast(page);
					f_node->page = page;

					if (!f_node) { 
						put_page(page);
						continue;
					}

					bitmap_shift_right(f_node->freq_bitmap, f_node->freq_bitmap, 1,
							FREQ_BITMAP_SIZE);

					if (page_is_idle(page)) {
						bitmap_clear(f_node->freq_bitmap, FREQ_BITMAP_SIZE-1, 1);
					} else {
						bitmap_set(f_node->freq_bitmap, FREQ_BITMAP_SIZE-1, 1);
					}

					frequency_update(f_node);
					set_page_idle(page);
					put_page(page);

					if ((freq_scan_count % SEC_SCAN_COUNT) == 0) {
						unsigned int weight = 0, i = 0;
						if (!spin_trylock(&osa_page_set_lock))
							continue;

						//Clear osa_flag to enable re-aggregation
						if ((freq_scan_count & 0xff) == 0)
							clear_bit(OSA_PF_AGGR, &page->osa_flag);

						for (i = FREQ_BITMAP_SIZE - 1; i > FREQ_BITMAP_SIZE - 5; i--) 
							if (test_bit(i, f_node->freq_bitmap))
								weight++;

						if (weight == 4) {
							list_add(&f_node->link, &osa_hot_page_set[0]);
							count[0]++;
						}

						spin_unlock(&osa_page_set_lock);
					}
				}
			}

			pagevec_remove_exceptionals(&pvec);
			pagevec_release(&pvec);
			cond_resched();
			index++;
		}

		iput(toput_inode);
		toput_inode = inode;

		spin_lock(&sb->s_inode_list_lock);

	}
	spin_unlock(&sb->s_inode_list_lock);
	iput(toput_inode);

	return ;
}

void osa_hpage_do_scan(void)
{
	struct mm_struct *mm;
	struct task_struct *tsk;
	struct osa_walker_stats walker_stats; 
	int err, i;

	/* check the performance of this function */
	drain_all_pages(NULL);

	freq_scan_count &= 0xffffffff;

	freq_scan_count++;

	if ((freq_scan_count % SEC_SCAN_COUNT) == 0) {
		spin_lock(&osa_page_set_lock);

		for (i = 0; i < 5; i++) {
			INIT_LIST_HEAD(&osa_hot_page_set[i]);
			count[i] = 0;
		}

		spin_unlock(&osa_page_set_lock);
	}


	// Scanning per-application anonymous pages
	list_for_each_entry_rcu(mm, &osa_hpage_scan_list, osa_hpage_scan_link) {
		if (!mm) 
			continue;

		if (atomic_read(&mm->mm_users) == 0)
			continue;

		// for debugging
		if (!mm->hpage_stats.weight)
			continue;

		rcu_read_lock();
		tsk = rcu_dereference(mm->owner);

        if (!tsk) 
            goto unlock_exit;

		if (atomic_read(&(tsk)->usage) == 0)
			goto unlock_exit;

		get_task_struct(tsk);
		mm = get_task_mm(tsk);
		rcu_read_unlock();

		VM_BUG_ON(!mm);

		memset(&walker_stats, 0, sizeof(struct osa_walker_stats));
		err = osa_hpage_do_walk(mm, &walker_stats);

		if (!err) {
			trace_printk("[%d] pid %d: \n\tidle_hpage %u hpage %u idle_bpage %lu bpage %lu\n",
					current->pid, tsk->pid, 
					walker_stats.idle_hpage_count,
					walker_stats.total_hpage_count,
					walker_stats.idle_bpage_count,
					walker_stats.total_bpage_count);
			/*
			trace_printk("[%d] pid %d: hit %u miss %u\n",
					current->pid, tsk->pid, 
					walker_stats.hit, walker_stats.miss);
			*/
			/*
			trace_printk("[%d] pid %d: nopromote %lu\n",
					current->pid, tsk->pid, 
					walker_stats.nopromote);
			trace_printk("count(0) = %lu, count(1) = %lu, count(2) = %lu "
					"count(3) = %lu, count(4) = %lu\n",
					count[0], count[1], count[2], count[3], count[4]);
			*/
		}

		mmput(mm);
		put_task_struct(tsk);
	}

	// Scanning page cache pages for gfn aggregation. currently disabled.
#if 0
	{
		iterate_supers(osa_page_cache_scan, NULL);
	}
#endif

	//Create aggregation candidate list for secondary scanning
	if (aggregation_sleep_millisecs && 
			((freq_scan_count % SEC_SCAN_COUNT) == 0)) {
		util_node_t *util_node, *tmp;
		aggr_node_t *aggr_node;
		unsigned int count = 0;
		list_for_each_entry_safe(util_node, tmp, 
				&osa_hot_page_set[0], link)  {

			//Max limit: 400MB
			if (count > (300 << 8))
				break;

			aggr_node = osa_aggr_node_alloc();
			if (!aggr_node) {
				trace_printk("Cannot allocate aggr_node\n");
				continue;
			}

			aggr_node->page = util_node->page;
			/*
			// detach from hotpage set
			list_del(&util_node->link);
			*/
			INIT_LIST_HEAD(&aggr_node->link);
			list_add(&aggr_node->link, &osa_aggregation_list);

			count++;
		}
		trace_printk("trigger secondary scanning with %d pages\n", count);
		wake_up_interruptible(&osa_aggregationd_wait);
	}

#if 0
	//entire physical page scan: only used for debugging
	{
	unsigned long pfn;
	struct page *page;
	//struct page_ext *page_ext;
	unsigned long total_file_mapped = 1; //avoid divided by zero
	unsigned long idle_file_mapped = 0;

	/* Buffer cache scanning */
	/* It might be overlapped with idle tracking in the above page walker
	 * when app do mmap with file. Deal with the case */
	pfn = min_low_pfn;

	while (!pfn_valid(pfn) && (pfn & (MAX_ORDER_NR_PAGES - 1)) != 0)
		pfn++;

	for (; pfn < max_pfn; pfn++) {
		if ((pfn & (MAX_ORDER_NR_PAGES - 1)) == 0 && !pfn_valid(pfn)) {
			pfn += MAX_ORDER_NR_PAGES - 1;
			continue;
		}

		/* Check for holes within a MAX_ORDER area */
		if (!pfn_valid_within(pfn))
			continue;

		//page = pfn_to_page(pfn);
		page = page_idle_get_page(pfn);

		// checked only filemapped page
		if (page && PageMappedToDisk(page)) {
			//page_ext = lookup_page_ext(page);

			total_file_mapped++;
			if (page_is_idle(page))
				idle_file_mapped++;
			
			set_page_idle(page);
			put_page(page);
		}
	}

	trace_printk("idle file page %lu, total file page %lu (ratio %ld) \n",
			idle_file_mapped, total_file_mapped, 
			(idle_file_mapped * 100) / total_file_mapped);
	}
#endif

	return;

unlock_exit:
	rcu_read_unlock();
	return;
}

static int osa_hpage_scand_has_work(void)
{
	return scan_sleep_millisecs && !list_empty(&osa_hpage_scan_list);
}

static int osa_hpage_scand_wait_event(void)
{
#ifdef SCAN_WQ
	return scan_sleep_millisecs && !list_empty(&osa_hpage_scan_list);
#else
	return scan_sleep_millisecs && 
        (!list_empty(&osa_hpage_scan_list) || kthread_should_stop());
#endif
}

static void osa_hpage_scand_wait_work(void) 
{
	if (osa_hpage_scand_has_work()) {
		wait_event_freezable_timeout(osa_hpage_scand_wait,
				0,
				msecs_to_jiffies(scan_sleep_millisecs));
	}

	if (thp_enabled)
		wait_event_freezable(osa_hpage_scand_wait, osa_hpage_scand_wait_event());
}

#ifdef SCAND_WQ
static void osa_hpage_scand(struct work_struct *ws)
{
	set_freezable();
	set_user_nice(current, MAX_NICE);

	while(1) {
		osa_hpage_do_scan();
		osa_hpage_scand_wait_work();
	}

	return ;
}

static int start_stop_osa_hpage_scand(void)
{
	int err = 0;

	if (thp_enabled) {
		if (!osa_hpage_scand_wq) {
			osa_hpage_scand_wq = create_singlethread_workqueue("osa_hpage_scand");

			if (osa_hpage_scand_wq) {
				//schedule_work(osa_hpage_scan_work);
				INIT_WORK(&osa_hpage_scan_work, osa_hpage_scand);
				queue_work(osa_hpage_scand_wq, &osa_hpage_scan_work);
			}
		}

		if (!list_empty(&osa_hpage_scan_list))
			wake_up_interruptible(&osa_hpage_scand_wait);
		
		if (!osa_aggregation_kthread) {
			osa_aggregation_kthread = kthread_run(osa_aggregationd, NULL, 
					"osa_aggregationd");
			if (unlikely(IS_ERR(osa_aggregation_kthread))) {
				pr_err("osa_aggregationd: kthread_run(osa_aggregationd) failed\n");
				err = PTR_ERR(osa_aggregation_kthread);
				osa_aggregation_kthread = NULL;
				goto fail;
			}
		}

		if (!list_empty(&osa_aggregation_list))
			wake_up_interruptible(&osa_aggregationd_wait);

	} else if (osa_aggregation_kthread) {
		// TODO: stop workqueue
		kthread_stop(osa_aggregation_kthread);
		osa_aggregation_kthread = NULL;
	}

fail:
	return err;
}
#else

/* Scanning kthread to gather hugepage stat and idle hugepage tracking */
static int osa_hpage_scand(void *none)
{
	set_freezable();
	set_user_nice(current, MAX_NICE);

	while(!kthread_should_stop()) {
		osa_hpage_do_scan();
		osa_hpage_scand_wait_work();
	}

	return 0;
}

static int start_stop_osa_hpage_scand(void)
{
	int err = 0;
	if (thp_enabled) {
		if (!osa_hpage_scand_kthread) {
			osa_hpage_scand_kthread = kthread_run(osa_hpage_scand, NULL, 
					"osa_hpage_scand");
			if (unlikely(IS_ERR(osa_hpage_scand_kthread))) {
				pr_err("osa_hpage_scand: kthread_run(osa_hpage_scand) failed\n");
				err = PTR_ERR(osa_hpage_scand_kthread);
				osa_hpage_scand_kthread = NULL;
				goto fail;
			}
		}

		if (!list_empty(&osa_hpage_scan_list))
			wake_up_interruptible(&osa_hpage_scand_wait);

		if (!osa_aggregation_kthread) {
			osa_aggregation_kthread = kthread_run(osa_aggregationd, NULL, 
					"osa_aggregationd");
			if (unlikely(IS_ERR(osa_aggregation_kthread))) {
				pr_err("osa_aggregationd: kthread_run(osa_aggregationd) failed\n");
				err = PTR_ERR(osa_aggregation_kthread);
				osa_aggregation_kthread = NULL;
				goto fail;
			}
		}

		if (!list_empty(&osa_aggregation_list))
			wake_up_interruptible(&osa_aggregationd_wait);

	} else if (osa_hpage_scand_kthread) {
		kthread_stop(osa_hpage_scand_kthread);
		osa_hpage_scand_kthread = NULL;

		kthread_stop(osa_aggregation_kthread);
		osa_aggregation_kthread = NULL;
	}

fail:
	return err;
}
#endif

static int osa_hpage_compactd_wait_event(void)
{
	return compact_sleep_millisecs || kthread_should_stop();
}

static void osa_hpage_check_and_do_compact(void)
{
	pg_data_t *pgdat;
	loff_t node = 1;
	struct zone *_zone = NULL; 
    unsigned long contig_pages_consumed = 0, order_to_compacted = 0;
    struct contig_page_info info;
    int i;

    // For each NUMA node.
	for (pgdat = first_online_pgdat();
			pgdat && node;
			pgdat = next_online_pgdat(pgdat)) {
        for (i = 0; i < pgdat->nr_zones; i++) {
            // Skip ZONE_DMA
            if (i < 1)
                continue;
            _zone = &pgdat->node_zones[i];

            fill_contig_page_info(_zone, 10, &info);
            contig_pages_consumed += info.free_pages_suitable;
            trace_printk("zone %s: %d\n", 
                    _zone->name, fragmentation_index(_zone, 10));
        }

        if (free_contig_pages_consumed >= contig_pages_consumed) {
            trace_printk("C: %lu\n", 
                    free_contig_pages_consumed - contig_pages_consumed);

            order_to_compacted = 
                    (free_contig_pages_consumed - contig_pages_consumed) >> 9;
        } else
            trace_printk("G: %lu\n", 
                    contig_pages_consumed - free_contig_pages_consumed);

		compact_pgdat_periodic(pgdat, 9);

        free_contig_pages_consumed = contig_pages_consumed;
    }

    return;
}

static void osa_hpage_compactd_wait_work(void)
{
    wait_event_freezable_timeout(osa_hpage_compactd_wait,
            kthread_should_stop(),
            msecs_to_jiffies(compact_sleep_millisecs));
    
    if (!compact_sleep_millisecs)
		wait_event_freezable(osa_hpage_compactd_wait, 
                osa_hpage_compactd_wait_event());
}

static int osa_hpage_compactd(void *none)
{
	set_freezable();
	set_user_nice(current, MAX_NICE);

	while(!kthread_should_stop()) {
		if (compact_sleep_millisecs)
			osa_hpage_check_and_do_compact();
        osa_hpage_compactd_wait_work();
	}

    return 0;
}

static int start_stop_osa_hpage_compactd(void)
{
	int err = 0;

	if (thp_enabled) {
		if (!osa_hpage_compactd_kthread) {
			osa_hpage_compactd_kthread = kthread_run(osa_hpage_compactd, NULL, 
					"osa_hpage_compactd");
			if (unlikely(IS_ERR(osa_hpage_compactd_kthread))) {
				pr_err("osa_hpage_compactd: kthread_run failed\n");
				err = PTR_ERR(osa_hpage_compactd_kthread);
				osa_hpage_compactd_kthread = NULL;
				goto fail;
			}
		}

        free_contig_pages_consumed = 0;
	    wake_up_interruptible(&osa_hpage_compactd_wait);

	} else if (osa_hpage_compactd_kthread) {
		kthread_stop(osa_hpage_compactd_kthread);
		osa_hpage_compactd_kthread = NULL;
	}

fail:
	return err;
}

/* sysfs interface */
#ifdef CONFIG_SYSFS
static ssize_t distance_divisor_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", distance_divisor);
}
static ssize_t distance_divisor_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	unsigned long divisor;
	int err;

	err = kstrtoul(buf, 10, &divisor);
	if (err || divisor > UINT_MAX)
		return -EINVAL;

	distance_divisor = divisor;

	return count;
}
static struct kobj_attribute distance_divisor_attr =
	__ATTR(distance_divisor, 0644, distance_divisor_show, 
			distance_divisor_store);

static ssize_t compact_sleep_millisecs_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", compact_sleep_millisecs);
}
static ssize_t compact_sleep_millisecs_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	unsigned long msecs;
	int err;

	err = kstrtoul(buf, 10, &msecs);
	if (err || msecs > UINT_MAX)
		return -EINVAL;

	compact_sleep_millisecs = msecs;
	wake_up_interruptible(&osa_hpage_compactd_wait);

	return count;
}
static struct kobj_attribute compact_sleep_millisecs_attr =
	__ATTR(compact_sleep_millisecs, 0644, compact_sleep_millisecs_show, 
			compact_sleep_millisecs_store);

static ssize_t scan_sleep_millisecs_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", scan_sleep_millisecs);
}
static ssize_t scan_sleep_millisecs_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	unsigned long msecs;
	int err;

	err = kstrtoul(buf, 10, &msecs);
	if (err || msecs > UINT_MAX)
		return -EINVAL;

	scan_sleep_millisecs = msecs;
	wake_up_interruptible(&osa_hpage_scand_wait);

	return count;
}

static struct kobj_attribute scan_sleep_millisecs_attr =
	__ATTR(scan_sleep_millisecs, 0644, scan_sleep_millisecs_show, 
			scan_sleep_millisecs_store);

static ssize_t aggregation_sleep_millisecs_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", aggregation_sleep_millisecs);
}
static ssize_t aggregation_sleep_millisecs_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	unsigned long msecs;
	int err;

	err = kstrtoul(buf, 10, &msecs);
	if (err || msecs > UINT_MAX)
		return -EINVAL;

	aggregation_sleep_millisecs = msecs;
	wake_up_interruptible(&osa_aggregationd_wait);

	return count;
}
static struct kobj_attribute aggregation_sleep_millisecs_attr =
	__ATTR(aggregation_sleep_millisecs, 0644, aggregation_sleep_millisecs_show, 
			aggregation_sleep_millisecs_store);

static ssize_t util_threshold_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", util_threshold);
}

static ssize_t util_threshold_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	int value;
	int err;

	err = kstrtoint(buf, 10, &value);
	if (err || value > 100 || value < 0)
		return -EINVAL;

	util_threshold = value;

	return count;
}
static struct kobj_attribute util_threshold_attr =
	__ATTR(util_threshold, 0644, util_threshold_show, util_threshold_store);

static ssize_t deferred_mode_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	switch(deferred_mode) {
		case 0:
			return sprintf(buf, "%u - default\n", deferred_mode);
		case 1:
			return sprintf(buf, "%u - async. promotion\n", deferred_mode);
		case 2:
			return sprintf(buf, "%u - async. promotion & sampling-based scanning\n", deferred_mode);
		case 3:
			return sprintf(buf, "%u - async. & frequency-based promotion & " 
					"sampling-based scanning\n", deferred_mode);
		default:
			return sprintf(buf, "%u - unknown\n", deferred_mode);
	}
}

static ssize_t deferred_mode_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	unsigned int value;
	int err;

	err = kstrtouint(buf, 10, &value);
	if (err || value > 3)
		return -EINVAL;

	deferred_mode = value;

	return count;
}
static struct kobj_attribute deferred_mode_attr =
	__ATTR(deferred_mode, 0644, deferred_mode_show, deferred_mode_store);

static ssize_t fairness_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	if (hugepage_fairness == 1) {
		return sprintf(buf, "enabled\n");
	}
	else if (hugepage_fairness == 0)
		return sprintf(buf, "disabled\n");
	else
		return sprintf(buf, "invalid value\n");

	return 0;
}
static ssize_t fairness_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	int err;
	unsigned long do_hugepage_fairness;

	err = kstrtoul(buf, 10, &do_hugepage_fairness);
	if (err || do_hugepage_fairness > 1)
		return -EINVAL;

	hugepage_fairness = do_hugepage_fairness;

	err = start_stop_osa_hpage_scand();
	
	if (err)
		return err;

	if (do_hugepage_fairness == 1)
		wake_up_interruptible(&osa_hpage_scand_wait);

	return count;
}
static struct kobj_attribute fairness_attr =
	__ATTR(fairness, 0644, fairness_show, fairness_store);

static struct attribute *osa_hugepage_attr[] = {
	&fairness_attr.attr,
	&deferred_mode_attr.attr,
	&util_threshold_attr.attr,
	&scan_sleep_millisecs_attr.attr,
	&aggregation_sleep_millisecs_attr.attr,
	&compact_sleep_millisecs_attr.attr,
	&distance_divisor_attr.attr,
	NULL,
};

static struct attribute_group osa_hugepage_attr_group = {
	.attrs = osa_hugepage_attr,
};

static int osa_hugepage_init_sysfs(struct kobject **hugepage_kobj)
{
	int err;

	*hugepage_kobj = kobject_create_and_add("ingens", 
			sysfs_hugepage_kobj);

	if (unlikely(!*hugepage_kobj)) {
		pr_err("failed to create ingens sys kobject\n");
		return -ENOMEM;
	}

	err = sysfs_create_group(*hugepage_kobj, &osa_hugepage_attr_group);
	if (err) {
		pr_err("failed to register ingens sys group\n");
		goto delete_kobj;
	}

	return 0;

delete_kobj:
	kobject_put(*hugepage_kobj);
	return err;
}

static void osa_hugepage_exit_sysfs(struct kobject *hugepage_kobj)
{
	sysfs_remove_group(hugepage_kobj, &osa_hugepage_attr_group);
	kobject_put(hugepage_kobj);
}

#else
static int osa_hugepage_init_sysfs(struct kobject **hugepage_kobj)
{
	return 0;
}

static void osa_hugepage_exit_sysfs(struct kobject *hugepage_kobj)
{
}
#endif

static int __init osa_hugepage_init(void)
{
	int err;
	struct kobject *hugepage_kobj;

	INIT_LIST_HEAD(&osa_hpage_scan_list);
	{
		int i;
		for (i = 0; i < 5; i++) 
			INIT_LIST_HEAD(&osa_hot_page_set[i]);
	}

	INIT_LIST_HEAD(&osa_aggregation_list);

	err = start_stop_osa_hpage_scand();
	if (err)
		goto err_sysfs;

	err = start_stop_osa_hpage_compactd();
	if (err)
		goto err_sysfs;

	/* init sysfs */
	err = osa_hugepage_init_sysfs(&hugepage_kobj);
	if (err)
		goto err_sysfs;

	return 0;

	/* not need yet */
	osa_hugepage_exit_sysfs(hugepage_kobj);
err_sysfs:
	return err;
}
subsys_initcall(osa_hugepage_init);
