#ifndef _OSA_H_
#define _OSA_H_
#include <linux/mm.h>

#define AGGR_BITMAP_SIZE 4

//Page flags for osa_flag in struct page
#define OSA_PF_AGGR 0x1 //Page is aggregated by osa_hpage_scand

extern spinlock_t osa_hpage_list_lock;

/* SLAB cache for worklist node */
extern struct kmem_cache *osa_poplmap_node_cachep;
extern struct kmem_cache *osa_work_node_cachep;
extern struct kmem_cache *osa_aggregate_node_cachep;

typedef struct osa_aggregation_node {
	struct list_head link;
	struct page *page;
	DECLARE_BITMAP(access_bitmap, AGGR_BITMAP_SIZE);
} aggr_node_t;

typedef struct population_node {
    //bitmap for tracking spatial utilization of 2MB region.
    DECLARE_BITMAP(popl_bitmap, 512);
    u8 committed;
} popl_node_t;

void *osa_popl_node_lookup(struct mm_struct *mm,
		unsigned long address);
int osa_popl_node_insert(struct mm_struct *mm, 
		unsigned long address,
		popl_node_t *node);
void *osa_popl_node_delete(struct mm_struct *mm, 
		unsigned long address);

extern spinlock_t osa_poplmap_lock;

popl_node_t *osa_poplmap_node_alloc(void);
void osa_poplmap_node_free(popl_node_t *node);

int osa_util_node_insert(struct mm_struct *mm, 
		unsigned long address,
		util_node_t *node);
void *osa_util_node_delete(struct mm_struct *mm, 
		unsigned long address);
void *osa_util_node_lookup(struct mm_struct *mm,
		unsigned long address);
void osa_clear_poplmap_range(struct mm_struct *mm, 
		unsigned long start, unsigned long end); 
void frequency_update(util_node_t *node);

unsigned long osa_get_hpage_count(struct mm_struct *mm);
void osa_hpage_enter_list(struct mm_struct *mm);
void osa_hpage_exit_list(struct mm_struct *mm);

extern long madvise_vma(struct vm_area_struct *vma, 
		struct vm_area_struct **prev,
		unsigned long start, unsigned long end, int behavior);

int is_member_of_scan_list(struct mm_struct *mm);
unsigned int osa_compute_fairness_metric(struct mm_struct *mm);

#define MAX_WORKLIST_SIZE 513
extern struct list_head hugepage_worklist;

typedef struct work_node {
    struct list_head list;
    struct mm_struct *mm;
    unsigned long address;
} work_node_t;

work_node_t *osa_work_node_alloc(void);
void osa_work_node_free(work_node_t *node);

extern spinlock_t worklist_lock;

extern wait_queue_head_t osa_hpage_scand_wait;
extern wait_queue_head_t osa_aggregationd_wait;
extern int osa_inst_get_page_owner(struct page *page, int references);

#endif 
