#undef TRACE_SYSTEM
#define TRACE_SYSTEM vmscan

#if !defined(_TRACE_VMSCAN_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_VMSCAN_H

#include <linux/types.h>
#include <linux/tracepoint.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <trace/events/gfpflags.h>

#define RECLAIM_WB_ANON		0x0001u
#define RECLAIM_WB_FILE		0x0002u
#define RECLAIM_WB_MIXED	0x0010u
#define RECLAIM_WB_SYNC		0x0004u /* Unused, all reclaim async */
#define RECLAIM_WB_ASYNC	0x0008u

#define show_reclaim_flags(flags)				\
	(flags) ? __print_flags(flags, "|",			\
		{RECLAIM_WB_ANON,	"RECLAIM_WB_ANON"},	\
		{RECLAIM_WB_FILE,	"RECLAIM_WB_FILE"},	\
		{RECLAIM_WB_MIXED,	"RECLAIM_WB_MIXED"},	\
		{RECLAIM_WB_SYNC,	"RECLAIM_WB_SYNC"},	\
		{RECLAIM_WB_ASYNC,	"RECLAIM_WB_ASYNC"}	\
		) : "RECLAIM_WB_NONE"

#define trace_reclaim_flags(page) ( \
	(page_is_file_cache(page) ? RECLAIM_WB_FILE : RECLAIM_WB_ANON) | \
	(RECLAIM_WB_ASYNC) \
	)

#define trace_shrink_flags(file) \
	( \
		(file ? RECLAIM_WB_FILE : RECLAIM_WB_ANON) | \
		(RECLAIM_WB_ASYNC) \
	)

TRACE_EVENT(mm_vmscan_kswapd_sleep,

	TP_PROTO(int nid),

	TP_ARGS(nid),

	TP_STRUCT__entry(
		__field(	int,	nid	)
	),

	TP_fast_assign(
		__entry->nid	= nid;
	),

	TP_printk("nid=%d", __entry->nid)
);

TRACE_EVENT(mm_vmscan_kswapd_wake,

	TP_PROTO(int nid, int order),

	TP_ARGS(nid, order),

	TP_STRUCT__entry(
		__field(	int,	nid	)
		__field(	int,	order	)
	),

	TP_fast_assign(
		__entry->nid	= nid;
		__entry->order	= order;
	),

	TP_printk("nid=%d order=%d", __entry->nid, __entry->order)
);

TRACE_EVENT(mm_vmscan_wakeup_kswapd,

	TP_PROTO(int nid, int zid, int order),

	TP_ARGS(nid, zid, order),

	TP_STRUCT__entry(
		__field(	int,		nid	)
		__field(	int,		zid	)
		__field(	int,		order	)
	),

	TP_fast_assign(
		__entry->nid		= nid;
		__entry->zid		= zid;
		__entry->order		= order;
	),

	TP_printk("nid=%d zid=%d order=%d",
		__entry->nid,
		__entry->zid,
		__entry->order)
);

DECLARE_EVENT_CLASS(mm_vmscan_direct_reclaim_begin_template,

	TP_PROTO(int order, int may_writepage, gfp_t gfp_flags),

	TP_ARGS(order, may_writepage, gfp_flags),

	TP_STRUCT__entry(
		__field(	int,	order		)
		__field(	int,	may_writepage	)
		__field(	gfp_t,	gfp_flags	)
	),

	TP_fast_assign(
		__entry->order		= order;
		__entry->may_writepage	= may_writepage;
		__entry->gfp_flags	= gfp_flags;
	),

	TP_printk("order=%d may_writepage=%d gfp_flags=%s",
		__entry->order,
		__entry->may_writepage,
		show_gfp_flags(__entry->gfp_flags))
);

DEFINE_EVENT(mm_vmscan_direct_reclaim_begin_template, mm_vmscan_direct_reclaim_begin,

	TP_PROTO(int order, int may_writepage, gfp_t gfp_flags),

	TP_ARGS(order, may_writepage, gfp_flags)
);

DEFINE_EVENT(mm_vmscan_direct_reclaim_begin_template, mm_vmscan_memcg_reclaim_begin,

	TP_PROTO(int order, int may_writepage, gfp_t gfp_flags),

	TP_ARGS(order, may_writepage, gfp_flags)
);

DEFINE_EVENT(mm_vmscan_direct_reclaim_begin_template, mm_vmscan_memcg_softlimit_reclaim_begin,

	TP_PROTO(int order, int may_writepage, gfp_t gfp_flags),

	TP_ARGS(order, may_writepage, gfp_flags)
);

DECLARE_EVENT_CLASS(mm_vmscan_direct_reclaim_end_template,

	TP_PROTO(unsigned long nr_reclaimed),

	TP_ARGS(nr_reclaimed),

	TP_STRUCT__entry(
		__field(	unsigned long,	nr_reclaimed	)
	),

	TP_fast_assign(
		__entry->nr_reclaimed	= nr_reclaimed;
	),

	TP_printk("nr_reclaimed=%lu", __entry->nr_reclaimed)
);

DEFINE_EVENT(mm_vmscan_direct_reclaim_end_template, mm_vmscan_direct_reclaim_end,

	TP_PROTO(unsigned long nr_reclaimed),

	TP_ARGS(nr_reclaimed)
);

DEFINE_EVENT(mm_vmscan_direct_reclaim_end_template, mm_vmscan_memcg_reclaim_end,

	TP_PROTO(unsigned long nr_reclaimed),

	TP_ARGS(nr_reclaimed)
);

DEFINE_EVENT(mm_vmscan_direct_reclaim_end_template, mm_vmscan_memcg_softlimit_reclaim_end,

	TP_PROTO(unsigned long nr_reclaimed),

	TP_ARGS(nr_reclaimed)
);

TRACE_EVENT(mm_shrink_slab_start,
	TP_PROTO(struct shrinker *shr, struct shrink_control *sc,
		long nr_objects_to_shrink, unsigned long pgs_scanned,
		unsigned long lru_pgs, unsigned long cache_items,
		unsigned long long delta, unsigned long total_scan),

	TP_ARGS(shr, sc, nr_objects_to_shrink, pgs_scanned, lru_pgs,
		cache_items, delta, total_scan),

	TP_STRUCT__entry(
		__field(struct shrinker *, shr)
		__field(void *, shrink)
		__field(int, nid)
		__field(long, nr_objects_to_shrink)
		__field(gfp_t, gfp_flags)
		__field(unsigned long, pgs_scanned)
		__field(unsigned long, lru_pgs)
		__field(unsigned long, cache_items)
		__field(unsigned long long, delta)
		__field(unsigned long, total_scan)
	),

	TP_fast_assign(
		__entry->shr = shr;
		__entry->shrink = shr->scan_objects;
		__entry->nid = sc->nid;
		__entry->nr_objects_to_shrink = nr_objects_to_shrink;
		__entry->gfp_flags = sc->gfp_mask;
		__entry->pgs_scanned = pgs_scanned;
		__entry->lru_pgs = lru_pgs;
		__entry->cache_items = cache_items;
		__entry->delta = delta;
		__entry->total_scan = total_scan;
	),

	TP_printk("%pF %p: nid: %d objects to shrink %ld gfp_flags %s pgs_scanned %ld lru_pgs %ld cache items %ld delta %lld total_scan %ld",
		__entry->shrink,
		__entry->shr,
		__entry->nid,
		__entry->nr_objects_to_shrink,
		show_gfp_flags(__entry->gfp_flags),
		__entry->pgs_scanned,
		__entry->lru_pgs,
		__entry->cache_items,
		__entry->delta,
		__entry->total_scan)
);

TRACE_EVENT(mm_shrink_slab_end,
	TP_PROTO(struct shrinker *shr, int nid, int shrinker_retval,
		long unused_scan_cnt, long new_scan_cnt, long total_scan),

	TP_ARGS(shr, nid, shrinker_retval, unused_scan_cnt, new_scan_cnt,
		total_scan),

	TP_STRUCT__entry(
		__field(struct shrinker *, shr)
		__field(int, nid)
		__field(void *, shrink)
		__field(long, unused_scan)
		__field(long, new_scan)
		__field(int, retval)
		__field(long, total_scan)
	),

	TP_fast_assign(
		__entry->shr = shr;
		__entry->nid = nid;
		__entry->shrink = shr->scan_objects;
		__entry->unused_scan = unused_scan_cnt;
		__entry->new_scan = new_scan_cnt;
		__entry->retval = shrinker_retval;
		__entry->total_scan = total_scan;
	),

	TP_printk("%pF %p: nid: %d unused scan count %ld new scan count %ld total_scan %ld last shrinker return val %d",
		__entry->shrink,
		__entry->shr,
		__entry->nid,
		__entry->unused_scan,
		__entry->new_scan,
		__entry->total_scan,
		__entry->retval)
);

DECLARE_EVENT_CLASS(mm_vmscan_lru_isolate_template,

	TP_PROTO(int order,
		unsigned long nr_requested,
		unsigned long nr_scanned,
		unsigned long nr_taken,
		isolate_mode_t isolate_mode,
		int file),

	TP_ARGS(order, nr_requested, nr_scanned, nr_taken, isolate_mode, file),

	TP_STRUCT__entry(
		__field(int, order)
		__field(unsigned long, nr_requested)
		__field(unsigned long, nr_scanned)
		__field(unsigned long, nr_taken)
		__field(isolate_mode_t, isolate_mode)
		__field(int, file)
	),

	TP_fast_assign(
		__entry->order = order;
		__entry->nr_requested = nr_requested;
		__entry->nr_scanned = nr_scanned;
		__entry->nr_taken = nr_taken;
		__entry->isolate_mode = isolate_mode;
		__entry->file = file;
	),

	TP_printk("isolate_mode=%d order=%d nr_requested=%lu nr_scanned=%lu nr_taken=%lu file=%d",
		__entry->isolate_mode,
		__entry->order,
		__entry->nr_requested,
		__entry->nr_scanned,
		__entry->nr_taken,
		__entry->file)
);

DEFINE_EVENT(mm_vmscan_lru_isolate_template, mm_vmscan_lru_isolate,

	TP_PROTO(int order,
		unsigned long nr_requested,
		unsigned long nr_scanned,
		unsigned long nr_taken,
		isolate_mode_t isolate_mode,
		int file),

	TP_ARGS(order, nr_requested, nr_scanned, nr_taken, isolate_mode, file)

);

DEFINE_EVENT(mm_vmscan_lru_isolate_template, mm_vmscan_memcg_isolate,

	TP_PROTO(int order,
		unsigned long nr_requested,
		unsigned long nr_scanned,
		unsigned long nr_taken,
		isolate_mode_t isolate_mode,
		int file),

	TP_ARGS(order, nr_requested, nr_scanned, nr_taken, isolate_mode, file)

);

TRACE_EVENT(mm_vmscan_writepage,

	TP_PROTO(struct page *page,
		int reclaim_flags),

	TP_ARGS(page, reclaim_flags),

	TP_STRUCT__entry(
		__field(unsigned long, pfn)
		__field(int, reclaim_flags)
	),

	TP_fast_assign(
		__entry->pfn = page_to_pfn(page);
		__entry->reclaim_flags = reclaim_flags;
	),

	TP_printk("page=%p pfn=%lu flags=%s",
		pfn_to_page(__entry->pfn),
		__entry->pfn,
		show_reclaim_flags(__entry->reclaim_flags))
);

TRACE_EVENT(mm_vmscan_lru_shrink_inactive,

	TP_PROTO(int nid, int zid,
			unsigned long nr_scanned, unsigned long nr_reclaimed,
			int priority, int reclaim_flags),

	TP_ARGS(nid, zid, nr_scanned, nr_reclaimed, priority, reclaim_flags),

	TP_STRUCT__entry(
		__field(int, nid)
		__field(int, zid)
		__field(unsigned long, nr_scanned)
		__field(unsigned long, nr_reclaimed)
		__field(int, priority)
		__field(int, reclaim_flags)
	),

	TP_fast_assign(
		__entry->nid = nid;
		__entry->zid = zid;
		__entry->nr_scanned = nr_scanned;
		__entry->nr_reclaimed = nr_reclaimed;
		__entry->priority = priority;
		__entry->reclaim_flags = reclaim_flags;
	),

	TP_printk("nid=%d zid=%d nr_scanned=%ld nr_reclaimed=%ld priority=%d flags=%s",
		__entry->nid, __entry->zid,
		__entry->nr_scanned, __entry->nr_reclaimed,
		__entry->priority,
		show_reclaim_flags(__entry->reclaim_flags))
);

TRACE_EVENT(mm_vmscan_lru_reclaim_stat, 

	TP_PROTO(int flag, int zone_idx, unsigned long nr_reclaimed, unsigned long anon_lru_size, 
		unsigned long file_lru_size, struct zone_reclaim_stat reclaim_stat),

	TP_ARGS(flag, zone_idx, nr_reclaimed, anon_lru_size, file_lru_size, reclaim_stat),

	TP_STRUCT__entry(
		__field(int, flag)
		__field(int, zone_idx)
		__field(unsigned long, nr_reclaimed)
		__field(unsigned long, anon_lru_size)
		__field(unsigned long, file_lru_size)
		__field(unsigned long, anon_nr_scanned)
		__field(unsigned long, anon_nr_rotated)
		__field(unsigned long, file_nr_scanned)
		__field(unsigned long, file_nr_rotated)
	),

	TP_fast_assign(
		__entry->flag = flag;
		__entry->zone_idx = zone_idx;
		__entry->nr_reclaimed = nr_reclaimed;
		__entry->anon_lru_size = anon_lru_size;
		__entry->file_lru_size = file_lru_size;
		__entry->anon_nr_scanned = reclaim_stat.recent_scanned[0];
		__entry->anon_nr_rotated = reclaim_stat.recent_rotated[0];
		__entry->file_nr_scanned = reclaim_stat.recent_scanned[1];
		__entry->file_nr_rotated = reclaim_stat.recent_rotated[1];
	),

	TP_printk("flag %d zone %d nr_reclaimed %lu anon lru_size %lu nr_scanned %lu nr_rotated %lu "
		"file lru_size %lu nr_scanned %lu nr_rotated %lu",
		__entry->flag,
		__entry->zone_idx,
		__entry->nr_reclaimed,
		__entry->anon_lru_size, 
		__entry->anon_nr_scanned, __entry->anon_nr_rotated,
		__entry->file_lru_size, 
		__entry->file_nr_scanned, __entry->file_nr_rotated
	)
);

TRACE_EVENT(mm_vmscan_reclaim_stat, 

	TP_PROTO(int flag, unsigned long nr_scanned, unsigned long nr_reclaimed),

	TP_ARGS(flag, nr_scanned, nr_reclaimed),

	TP_STRUCT__entry(
		__field(int, flag)
		__field(unsigned long, nr_scanned)
		__field(unsigned long, nr_reclaimed)
	),

	TP_fast_assign(
		__entry->flag = flag;
		__entry->nr_scanned = nr_scanned;
		__entry->nr_reclaimed = nr_reclaimed;
	),

	TP_printk("flag %d nr_scanned %lu nr_reclaimed %lu",
		__entry->flag,
		__entry->nr_scanned,
		__entry->nr_reclaimed
	)
);

/* flag 0 : reclaimed
 * flag 1 : under writeback (waiting for being reclaimed)
 * flag 5 : keep in the list 
 */
TRACE_EVENT(mm_vmscan_shrink_page_list,

	TP_PROTO(int flag, unsigned int owner, unsigned long pfn, 
		unsigned int is_huge, unsigned int ref_action),

	TP_ARGS(flag, owner, pfn, is_huge, ref_action),

	TP_STRUCT__entry(
		__field(int, flag)
		__field(unsigned int, owner)
		__field(unsigned long, pfn)
		__field(unsigned int, is_huge)
		__field(unsigned int, ref_action)
	),

	TP_fast_assign(
		__entry->flag = flag;
		__entry->owner = owner;
		__entry->pfn = pfn;
		__entry->is_huge = is_huge;
		__entry->ref_action = ref_action;
	),

	TP_printk("flag %d owner %u pfn %lx huge %u ref_action %u",
			__entry->flag, __entry->owner,
			__entry->pfn, __entry->is_huge, __entry->ref_action)
);

TRACE_EVENT(mm_vmscan_printk1,

	TP_PROTO(const char *str, unsigned long val),

	TP_ARGS(str, val),

	TP_STRUCT__entry(
		__array(char, str, 40)
		__field(unsigned long, val)
	),

	TP_fast_assign(
		strncpy(__entry->str, str, 40);
		__entry->str[40] = 0;
		__entry->val = val;
	),

	TP_printk("%s %lu", __entry->str, __entry->val)
);

TRACE_EVENT(mm_vmscan_printk2,

	TP_PROTO(const char *str1, unsigned long val1, 
		const char *str2, unsigned long val2),

	TP_ARGS(str1, val1, str2, val2),

	TP_STRUCT__entry(
		__array(char, str1, 40)
		__field(unsigned long, val1)
		__array(char, str2, 40)
		__field(unsigned long, val2)
	),

	TP_fast_assign(
		strncpy(__entry->str1, str1, 40);
		__entry->str1[40] = 0;
		__entry->val1 = val1;
		strncpy(__entry->str2, str2, 40);
		__entry->str2[40] = 0;
		__entry->val2 = val2;
	),

	TP_printk("%s %lu %s %lu", 
			__entry->str1, __entry->val1,
			__entry->str2, __entry->val2)
);

TRACE_EVENT(mm_vmscan_printk3,

	TP_PROTO(const char *str1, unsigned long val1, 
		const char *str2, unsigned long val2,
		const char *str3, unsigned long val3),

	TP_ARGS(str1, val1, str2, val2, str3, val3),

	TP_STRUCT__entry(
		__array(char, str1, 40)
		__field(unsigned long, val1)
		__array(char, str2, 40)
		__field(unsigned long, val2)
		__array(char, str3, 40)
		__field(unsigned long, val3)
	),

	TP_fast_assign(
		strncpy(__entry->str1, str1, 40);
		__entry->str1[40] = 0;
		__entry->val1 = val1;
		strncpy(__entry->str2, str2, 40);
		__entry->str2[40] = 0;
		__entry->val2 = val2;
		strncpy(__entry->str3, str3, 40);
		__entry->str3[40] = 0;
		__entry->val3 = val3;
	),

	TP_printk("%s %lu %s %lu %s %lu", 
			__entry->str1, __entry->val1,
			__entry->str2, __entry->val2,
			__entry->str3, __entry->val3
	)
);

TRACE_EVENT(mm_vmscan_printk4,

	TP_PROTO(const char *str1, unsigned long val1, 
		const char *str2, unsigned long val2,
		const char *str3, unsigned long val3,
		const char *str4, unsigned long val4),

	TP_ARGS(str1, val1, str2, val2, str3, val3, str4, val4),

	TP_STRUCT__entry(
		__array(char, str1, 40)
		__field(unsigned long, val1)
		__array(char, str2, 40)
		__field(unsigned long, val2)
		__array(char, str3, 40)
		__field(unsigned long, val3)
		__array(char, str4, 40)
		__field(unsigned long, val4)
	),

	TP_fast_assign(
		strncpy(__entry->str1, str1, 40);
		__entry->str1[40] = 0;
		__entry->val1 = val1;
		strncpy(__entry->str2, str2, 40);
		__entry->str2[40] = 0;
		__entry->val2 = val2;
		strncpy(__entry->str3, str3, 40);
		__entry->str3[40] = 0;
		__entry->val3 = val3;
		strncpy(__entry->str4, str4, 40);
		__entry->str4[40] = 0;
		__entry->val4 = val4;
	),

	TP_printk("%s %lu %s %lu %s %lu %s %lu", 
			__entry->str1, __entry->val1,
			__entry->str2, __entry->val2,
			__entry->str3, __entry->val3,
			__entry->str4, __entry->val4
	)
);

#endif /* _TRACE_VMSCAN_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
