/* SNU ARC Lab. mobile memory optimization */
#ifndef _ARC_AVAILABLE_LIST_H
#define _ARC_AVAILABLE_LIST_H

#include <asap/interface.h>
#include <linux/types.h>

#ifdef ENABLE_ASAP
#define MAX_HPOOL_SZ (1 << 18) // 131072 entries, (hentry size) * 128 KB 



struct anon_ptt_hentry {
        pid_t tgid; 
        unsigned long vaddr;
        struct hlist_node node;
        unsigned int tick;
};


struct file_ptt_lentry {
        //pid_t tgid; 
        //unsigned long vaddr;
        //pgoff_t index; // file_page_lentry is sorted by index
        pgoff_t start;
        pgoff_t len;
        struct file_ptt_lentry *next;
};

struct file_ptt_hentry {
        //unsigned long inum; 
        struct address_space *mapping;
        struct file_ptt_lentry *vaddr_list;
        unsigned int vaddr_list_len;
        int access;
        int touch;
        //bool valid;
        struct hlist_node node;
};

struct file_shadow_hentry {
        struct address_space *mapping;
        pgoff_t index;
        int cnt;
        struct hlist_node node;
};

struct apg_hentry {
        pid_t tgid;
        int cnt;
        struct hlist_node node;
};



void ptt_lentry_free(struct ptt *ptt, struct file_ptt_lentry *lentry);



/* av_list: struct hlist_head*, available_list of hentries 
 * lock: struct spin_lock*, spin_lock for available_list
 * type: type name of target hentry; ex. struct fileswap_hentry
 * member: member name in target hentry
 * flags: unsigned long flags for irqsave
 * hentry: return value, struct type* hentry to be used as ret entry 
 */
#define get_av_hentry(av_list, lock, type, member, flags, hentry) ({ \
        spin_lock_irqsave(lock, flags); \
        if (!hlist_empty(av_list)) { \
                hentry = hlist_entry((av_list)->first, type, member); \
		hlist_del(&hentry->member); \
        } else { \
                hentry = NULL; \
                print_asap(#type " available_list is exhausted") ; \
        } \
        spin_unlock_irqrestore(lock, flags); \
})

#define ret_av_hentry(av_list, lock, member, flags, hentry) ({ \
        spin_lock_irqsave(lock, flags); \
        hlist_add_head(&hentry->member, av_list); \
        spin_unlock_irqrestore(lock, flags);\
})

/* pool is not ptr */
#define init_av_list(av_list, lock, pool, member, pool_sz, idx, flags) ({ \
	spin_lock_irqsave(lock, flags); \
	for(idx = 0; idx < pool_sz; idx++) { \
		hlist_add_head(&pool[idx].member, av_list); \
	} \
	spin_unlock_irqrestore(lock, flags); \
})


#endif /* ENABLE_ASAP */
#endif /* _ARC_AVAILABLE_LIST_H */
