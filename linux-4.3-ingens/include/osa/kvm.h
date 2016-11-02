#ifndef _OSA_KVM_H_
#define _OSA_KVM_H_
#include <linux/kvm_host.h>

int osa_get_hpage_info(struct kvm *kvm, unsigned long gfn);

#endif
