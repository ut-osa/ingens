#include <osa/kvm.h>
#include <linux/printk.h>
#include <linux/mm_types.h>
#include <linux/page-flags.h>

int osa_get_hpage_info(struct kvm *kvm, unsigned long gfn)
{
	unsigned long pfn;
	struct page *page;
	pfn = gfn_to_pfn(kvm, gfn);

	if (is_error_noslot_pfn(pfn))
		return -EPERM;

	//printk("%lx %lx\n", gfn, pfn);
	
	page = pfn_to_page(pfn);

	if (page) {
		if (PageTransHuge(page))
			return 1;
	} else {
		return -EFAULT;
	}

	return 0;
}
