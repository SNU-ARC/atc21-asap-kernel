/* SNU ARC Lab. ASAP */
/* ptt.c
 * ptt implementation.
 * APIs implemented here are used in SFE updates and prepaging process
 * See ppthread.c and sysctl.c for the usage
 * */


#include <asap/interface.h>
#include <asap/available_list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/rwsem.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pagemap.h>

#ifdef ENABLE_ASAP
struct ptt *current_anon_ptt;
struct anon_table *current_anon_table;

struct anon_fault_buf_entry anon_fault_buf[FAULT_BUF_SZ];
unsigned int anon_fault_buf_len;

struct address_space *file_feedback_buf_mapping[FAULT_BUF_SZ];
int file_feedback_buf_idx[FAULT_BUF_SZ];
int file_feedback_buf_len;

struct ptt *current_file_ptt;
struct ptt *current_big_file_ptt;
struct ptt *current_file_ct;
struct kmem_cache *file_shadow_cache;

struct file_fault_buf_entry file_fault_buf[FAULT_BUF_SZ];
unsigned int file_fault_buf_len;


unsigned long anon_feedback_buf_va[FAULT_BUF_SZ];
pid_t anon_feedback_buf_tgid[FAULT_BUF_SZ];
unsigned int anon_feedback_buf_len;
static DEFINE_SPINLOCK(anon_feedback_buf_lock);


static void *ptt_slab_alloc(struct kmem_cache *cache) { 
                void *ret = kmem_cache_alloc(cache, GFP_KERNEL);
                if (!ret) {
                        printk("ARC ERROR: slab alloc failed\n");
                        return 0;
                }

                return ret;
}

void anon_table_init(struct anon_table *ant) {
    ant->ptt = (struct ptt *)vmalloc(sizeof(struct ptt));
    ant->ct = (struct ptt *)vmalloc(sizeof(struct ptt));
    ant->start_tick = default_tick;
    ptt_init(ant->ptt, 16, 1);
    ptt_init(ant->ct, 16, 1);
    ant->hentry_cache = kmem_cache_create("anon_ptt_hcache",
                sizeof(struct anon_ptt_hentry),
                0,
                0,
                NULL);
    ant->ptt->hentry_cache = ant->hentry_cache;
    ant->ct->hentry_cache = ant->hentry_cache;
}

//static unsigned int allocator_cnt;
/* Note: ptt is frozen at init */
void ptt_init(struct ptt *ptt, unsigned int fetch_unit, bool is_anon) {
        int idx;
        ptt->fetch_idx = 0;
        ptt->sz = 0;
        ptt->updatable = 0;
        ptt->fetch_unit = fetch_unit;
        hash_init(ptt->htable);
        spin_lock_init(&ptt->lock);
        ptt->is_anon = is_anon;

          if (is_anon) {
                ptt->lentry_cache = NULL;
        } else {
                ptt->hentry_cache = kmem_cache_create("file_ptt_hcache",
                                sizeof(struct file_ptt_hentry),
                                0,
                                0,
                                NULL);
                ptt->lentry_cache = kmem_cache_create("file_ptt_lcache",
                                sizeof(struct file_ptt_lentry),
                                0,
                                0,
                                NULL);
        }
        ptt->hentry_counter = 0;
        for (idx = 0; idx < (1 << PTT_INDEX_TB_BITS); idx++)
                ptt->index_table[idx] = -1;
}

/* internal */
void ptt_lentry_free(struct ptt *ptt, struct file_ptt_lentry *lentry) {
        struct file_ptt_lentry *tmp;
        while (lentry) {       
                tmp = lentry->next;
                kmem_cache_free(ptt->lentry_cache, lentry);
                lentry = tmp;
        }
}


void ptt_clear(struct ptt *ptt) {
        if (ptt->is_anon)
                anon_ptt_clear(ptt);
        else
                file_ptt_clear(ptt);
}

DEFINE_SPINLOCK(ptt_clear_lock);
void anon_ptt_clear(struct ptt *ptt) {
        int cursor, idx;
        struct anon_ptt_hentry *hentry; 
        struct hlist_node *tmp;
        unsigned long flags;
        //struct hlist_head *av_list = anon_av_lis;
        //struct spinlock_t *av_lock = ptt->is_anon ? anon_av_lock : file_av_lock;
        BUG_ON(!ptt->is_anon);
        //print_asap("ptt clear start");
        spin_lock_irqsave(&ptt_clear_lock, flags);
        ptt->fetch_idx = 0;
        ptt->sz = 0;
        ptt->updatable = 0;
        hash_for_each_safe(ptt->htable, cursor, tmp, hentry, node) {
                hash_del(&(hentry->node));        
                kmem_cache_free(ptt->hentry_cache, hentry);                
        }
        hash_init(ptt->htable);
        ptt->hentry_counter = 0;
        for (idx = 0; idx < (1 << PTT_INDEX_TB_BITS); idx++)
                ptt->index_table[idx] = -1;
        spin_unlock_irqrestore(&ptt_clear_lock, flags);
}

void file_ptt_clear(struct ptt *ptt) {
        int cursor, idx;
        struct file_ptt_hentry *hentry; 
        struct hlist_node *tmp;
        unsigned long flags; //av_flags;

        BUG_ON(ptt->is_anon);
        spin_lock_irqsave(&ptt_clear_lock, flags);
        ptt->fetch_idx = 0;
        ptt->sz = 0;
        ptt->updatable = 0;
        hash_for_each_safe(ptt->htable, cursor, tmp, hentry, node) {
                hash_del(&(hentry->node));        
                if (hentry->vaddr_list)
                        ptt_lentry_free(ptt, hentry->vaddr_list);
                
                kmem_cache_free(ptt->hentry_cache, hentry);                
                //ret_av_hentry(&av_list, &av_lock, node, av_flags, hentry); 
        }
        hash_init(ptt->htable);
        ptt->hentry_counter = 0;
        for (idx = 0; idx < (1 << PTT_INDEX_TB_BITS); idx++)
                ptt->index_table[idx] = -1;
        spin_unlock_irqrestore(&ptt_clear_lock, flags);
}



bool anon_ptt_is_in(struct ptt *ptt, pid_t tgid, unsigned long vaddr) {
        struct anon_ptt_hentry *hentry;
        
        BUG_ON(!ptt->is_anon);
        hash_for_each_possible(ptt->htable, hentry, node, (vaddr >> PAGE_SHIFT)) {
                if (hentry->tgid == tgid && hentry->vaddr == vaddr)
                        return 1;
        }
        return 0;
}

static bool interval_overlapped(unsigned long st1, unsigned long len1, 
                unsigned long st2, unsigned long len2, unsigned long spare) {
        unsigned long end1 = st1 + len1;
        unsigned long end2 = st2 + len2;

        spare = 0;
        if ((end1 >= st2 && st1 <= st2) || (end1 >= end2 && st1 <= end2))
                return 1; 
        if ((end2 >= st1 && st2 <= st1) || (end2 >= end1 && st2 <= end1))
                return 1;
        if (st2 <= end1 + spare && st2 >= end1)
                return 1;
        if (st1 <= end2 + spare && st1 >= end2)
                return 1;

        return 0;

}


int file_ptt_is_in(struct ptt *ptt, 
                struct address_space *mapping, 
                unsigned long start, 
                unsigned long len) {       
        struct file_ptt_hentry *hentry;
        BUG_ON(ptt->is_anon);
        hash_for_each_possible(ptt->htable, hentry, node, (unsigned long)mapping) { // file ptt uses inum as a hash key
                if (hentry->mapping == mapping) {
                        return 1;
                }
        }
        return 0;
}

int file_ptt_is_in_detail(struct ptt *ptt, 
                struct address_space *mapping, 
                unsigned long start, 
                unsigned long len) {       
        struct file_ptt_hentry *hentry;
        BUG_ON(ptt->is_anon);
        hash_for_each_possible(ptt->htable, hentry, node, (unsigned long)mapping) { // file ptt uses inum as a hash key
                if (hentry->mapping == mapping) {
                        struct file_ptt_lentry *lentry = hentry->vaddr_list;
                        while (lentry) {
                                if (interval_overlapped(start, len, lentry->start, lentry->len, 0))
                                        return 1;
                                lentry = lentry->next;
                        }
                }
        }
        return 0;
}

int file_ptt_del(struct ptt *ptt, 
                struct address_space *mapping, 
                unsigned long idx) {       
        struct file_ptt_hentry *hentry;
        BUG_ON(ptt->is_anon);
        hash_for_each_possible(ptt->htable, hentry, node, (unsigned long)mapping) { // file ptt uses inum as a hash key
                if (hentry->mapping == mapping) {
                        struct file_ptt_lentry *lentry = hentry->vaddr_list;
                        struct file_ptt_lentry *pentry = NULL;
                        while (lentry) {
                                if (lentry->start <= idx && lentry->start + lentry->len > idx) {
                                        if (lentry->len == 1) {
                                                if (!pentry)
                                                        hentry->vaddr_list = lentry->next; 
                                                else
                                                        pentry->next = lentry->next;
                                                kmem_cache_free(ptt->lentry_cache, lentry);
                                        } else if (lentry->start == idx)
                                                lentry->start = lentry->start + 1;
                                        else if (lentry->start + lentry->len - 1 == idx)
                                                lentry->len = lentry->len - 1;
                                        else {
                                                struct file_ptt_lentry *nentry = (struct file_ptt_lentry *)ptt_slab_alloc(ptt->lentry_cache);
                                                if (!nentry) 
                                                        return 0;
                                                nentry->start = idx + 1;
                                                nentry->len = lentry->len - idx + lentry->start - 1;
                                                nentry->next = lentry->next;
                                                lentry->len = idx - lentry->start;
                                                lentry->next = nentry;
                                        }
                                        return 1;
                                }
                                pentry = lentry;
                                lentry = lentry->next;
                        }
                }
        }
        return 0;
}




DEFINE_SPINLOCK(ptt_add_lock);
int anon_ptt_add(struct ptt *ptt, pid_t tgid, unsigned long vaddr) { 
        struct anon_ptt_hentry *hentry;
        //unsigned long flags;

        if (ptt->updatable) {
                //spin_lock_irqsave(&ptt_add_lock, flags);
                if ( anon_ptt_is_in(ptt, tgid, vaddr) || anon_ptt_is_in(current_anon_ptt, tgid, vaddr) ) {
                        //spin_unlock_irqrestore(&ptt_add_lock, flags);
                        return 0;
                }
                
                hentry = (struct anon_ptt_hentry *)ptt_slab_alloc(ptt->hentry_cache);
                if (!hentry){
                        print_asap("no hentry \n");
                        return 0;
                }
                        
                //get_av_hentry(&av_list, &av_lock, struct ptt_hentry, node, av_flags, hentry);
                //if (!hentry)
                //        return 0;
                hentry->vaddr = vaddr;
                hentry->tgid = tgid;
                hentry->tick = current_anon_table->start_tick;

                //print_asap("ARC anon_ptt_add new %lu %lu\n", tgid, vaddr);

                hash_add(ptt->htable, &hentry->node, (vaddr >> PAGE_SHIFT));
                ptt->sz++; 
                //ptt->list[ptt->sz++] = vaddr;
                //spin_unlock_irqrestore(&ptt_add_lock, flags); 
                return 1;
        }
        return 0;
}

int anon_ptt_check_access(pid_t tgid, unsigned long vaddr, bool isclear) {
    int ret;
    struct mm_struct *mm; 
    struct task_struct *task;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    pte_t entry;

    ret = -1;
    if (!switch_target_task) {
            print_asap("error - target task null");
            return ret;
    }
    
    //mm = switch_target_task->mm; 
    task = find_task_by_vpid(tgid);
    if (task) mm = task->mm;
    else return ret;

    if (!vaddr) return ret;

    /* page table walk */
    if(mm){
        pgd = pgd_offset(mm, vaddr);
        if (pgd_none(*pgd)) return ret;

        pud = pud_offset(pgd, vaddr);
        if (pud_none(*pud)) return ret;

        pmd = pmd_offset(pud, vaddr);
        if (pmd_none(*pmd)) return ret;

        pte = pte_offset_kernel(pmd, vaddr);
        if (!pte || pte_none(*pte)) return ret;

        if (pte_present(*pte)) {
            ret = 0;
            if (pte_young(*pte)) {                        
                    ret = 1;
                    if(isclear){
                        entry = pte_mkold(*pte); 
                        set_pte_at(mm, vaddr, pte, entry);

                    }
            }
        }
    }
    return ret;
}

//TODO : look around all
void anon_ptt_sweep(struct ptt *ptt, bool isct) {
    int cursor;
    struct anon_ptt_hentry *hentry; 
    struct hlist_node *tmp;
    unsigned long flags;
    BUG_ON(!ptt->is_anon);

    spin_lock_irqsave(&ptt_clear_lock, flags);
    hash_for_each_safe(ptt->htable, cursor, tmp, hentry, node) {
        //TODO :: only check entry that matches our activity
        hentry->tick--;
        switch(anon_ptt_check_access(hentry->tgid, hentry->vaddr, 0)){
            case -1 :
                //print_asap("anon_ptt_shadow_sweep non-existing %d %lu %lu\n", hentry->tick, hentry->tgid, hentry->vaddr);
                hash_del(&(hentry->node));        
                kmem_cache_free(ptt->hentry_cache, hentry);
                ptt->sz--;
                break;
            case 0 :
                if(!hentry->tick){
                    //print_asap("anon_ptt_shadow_sweep out-of-time %d %lu %lu\n", hentry->tick, hentry->tgid, hentry->vaddr);
                    hash_del(&(hentry->node));        
                    kmem_cache_free(ptt->hentry_cache, hentry);
                    ptt->sz--;
                }
                break;
            case 1 :
                hentry->tick = current_anon_table->start_tick;
                if(isct){
                        //print_asap("anon_ptt_shadow_sweep promote %d %lu %lu\n", hentry->tick, hentry->tgid, hentry->vaddr);
                        hash_del(&(hentry->node));        
                        hash_add(current_anon_ptt->htable, &hentry->node, (hentry->vaddr >> PAGE_SHIFT));
                        ptt->sz--;
                        current_anon_ptt->sz++;
                        
                }
                break;

        }
    }
    spin_unlock_irqrestore(&ptt_clear_lock, flags);
}


int anon_ptt_clearaccess(struct ptt *ptt) {
    int cursor;
    struct anon_ptt_hentry *hentry; 
    struct hlist_node *tmp;
    unsigned long flags;
    int cnt;

    BUG_ON(!ptt->is_anon);
    
    cnt =0;
    spin_lock_irqsave(&ptt_clear_lock, flags);
    hash_for_each_safe(ptt->htable, cursor, tmp, hentry, node) {
        //TODO :: only check entry that matches our activity
        cnt += anon_ptt_check_access(hentry->tgid, hentry->vaddr, 1) == 1;
    }
    spin_unlock_irqrestore(&ptt_clear_lock, flags);
    return cnt;
}


//int file_ptt_add(struct ptt *ptt, pid_t tgid, unsigned long inum, unsigned long vaddr) { 

static void merge_interval(unsigned long st1, unsigned long len1, 
                unsigned long st2, unsigned long len2, 
                unsigned long *new_st, unsigned long *new_len) {
        unsigned long end1 = st1 + len1;
        unsigned long end2 = st2 + len2;
        unsigned long new_end;

        //print_asap("merge_interval (%lu, %lu) (%lu, %lu)", st1, end1, st2, end2);

        if (st1 < st2)
                *new_st = st1;
        else 
                *new_st = st2;

        if (end1 > end2)
                new_end = end1;
        else
                new_end = end2;
        *new_len = new_end - *new_st + 1;
}

#define EXT_MAX_SZ 4096/8
void demote_extent(struct ptt *ptt, struct file_ptt_lentry *lentry) { 
        while (lentry->len >= EXT_MAX_SZ) {
                struct file_ptt_lentry *next_lentry = (struct file_ptt_lentry *)ptt_slab_alloc(ptt->lentry_cache);
                if (!next_lentry) // do it later
                        return;
                                                        
                next_lentry->next = lentry->next; 
                next_lentry->start = lentry->start + lentry->len - EXT_MAX_SZ;
                next_lentry->len = EXT_MAX_SZ;
                lentry->len = lentry->len - EXT_MAX_SZ;
                lentry->next = next_lentry; 
        }
}

static void _compact_one_file(struct ptt *ptt, struct file_ptt_lentry *vaddr_list, int spare) {
        struct file_ptt_lentry *start = vaddr_list;
        struct file_ptt_lentry *end = NULL;
        struct file_ptt_lentry *cursor = NULL;
        struct file_ptt_lentry *tmp = NULL;
        while ( start ) {
                // find end
                if ( !start->next )
                        break;
                cursor = start;
                while( cursor->next->start - cursor->start <= spare ) { 
                        cursor = cursor->next; 
                        if (!cursor->next)
                                break;
                }
                end = cursor;

                if ( start == end )
                        goto next;

                // merge
                start->len = end->start - start->start + 1;
                for ( cursor = start->next; cursor != end; cursor = tmp ) {
                        tmp = cursor->next;
                        kmem_cache_free(ptt->lentry_cache, cursor);
                }
                start->next = end->next; 
                kmem_cache_free(ptt->lentry_cache, end);
next:
                start = start->next;
        }
}


void file_ptt_compact(struct ptt *ptt, int spare) {
        int cursor;
        struct file_ptt_hentry *hentry;

        hash_for_each(ptt->htable, cursor, hentry, node) {
                _compact_one_file(ptt, hentry->vaddr_list, spare);
        }
}


int file_ptt_add_one(struct ptt *ptt, 
                struct address_space *mapping, 
                unsigned long index,
                int unit) { 
        struct file_ptt_hentry *hentry = 0;
        //unsigned long flags;
        int is_in;
        struct file_ptt_lentry *lentry;
        struct file_ptt_lentry *nentry;


        //struct task_struct *task = find_task_by_vpid(tgid);


        if (!mapping)
                return 0;

        if (!mapping_mapped(mapping))
                return 0; 

        if (!ptt->updatable)
                return 0;
                
        is_in = file_ptt_is_in(ptt, mapping, index, 1);

        //spin_lock_irqsave(&ptt_add_lock, flags);
        
        if ( !is_in ) {
                /* create hentry first if does not exist */
                hentry = (struct file_ptt_hentry *)ptt_slab_alloc(ptt->hentry_cache);
                if (!hentry) {
                        //spin_unlock_irqrestore(&ptt_add_lock, flags);
                        return 0;
                }
                hentry->mapping = mapping;
                hentry->vaddr_list = NULL; 
                hentry->vaddr_list_len = 0;
                hash_add(ptt->htable, &hentry->node, (unsigned long)mapping);
                //ptt->index_table[ptt->hentry_counter++] = hash_min((unsigned long)mapping, HASH_BITS(ptt->htable));
        } else {
                /* get hentry when exists */
                hash_for_each_possible(ptt->htable, hentry, node, (unsigned long)mapping) {
                        if (hentry->mapping == mapping) 
                                break;
                }
        }
        
        BUG_ON(!hentry);
        
        lentry = hentry->vaddr_list;
        nentry = (struct file_ptt_lentry *)ptt_slab_alloc(ptt->lentry_cache);
        if (!nentry) {
                //spin_unlock_irqrestore(&ptt_add_lock, flags);
                return 0;
        }
        /* sort by index */
        nentry->start = index;
        nentry->len = unit;
        nentry->next = NULL;
        if (!lentry) {
                hentry->vaddr_list = nentry;
                hentry->vaddr_list_len++;
        } else {
                struct file_ptt_lentry *pentry = NULL;
                if (hentry->vaddr_list->start == nentry->start) {
                        kmem_cache_free(ptt->lentry_cache, nentry);
                        //spin_unlock_irqrestore(&ptt_add_lock, flags);
                        return 0;
                } else if (hentry->vaddr_list->start > nentry->start) {
                        nentry->next = hentry->vaddr_list;
                        hentry->vaddr_list = nentry;
                } else {
                        pentry = hentry->vaddr_list;
                        lentry = hentry->vaddr_list->next;
                        while (lentry) {
                                if (lentry->start == nentry->start) {
                                        kmem_cache_free(ptt->lentry_cache, nentry);
                                        //spin_unlock_irqrestore(&ptt_add_lock, flags);
                                        return 0;
                                }
                                if (lentry->start > nentry->start) {
                                        nentry->next = lentry;
                                        pentry->next = nentry;
                                        break;
                                }
                                pentry = lentry;
                                lentry = lentry->next;
                        }
                        if (!lentry) {
                                nentry->next = NULL;
                                pentry->next = nentry;
                        }      
                }
                hentry->vaddr_list_len++;
        }

        //spin_unlock_irqrestore(&ptt_add_lock, flags);
        return 1;
}


int file_ptt_add(struct ptt *ptt, 
                struct address_space *mapping, 
                unsigned long start, 
                unsigned long len) { 
        struct file_ptt_hentry *hentry = 0;
        //unsigned long flags;
        //struct task_struct *task = find_task_by_vpid(tgid);

        //if (!task)
        //        return 0;

        if (!mapping)
                return 0;

        if (!mapping_mapped(mapping))
                return 0; 

        if (ptt->updatable) {
                int is_in = file_ptt_is_in(ptt, mapping, start, len);
                struct file_ptt_lentry *lentry;
                struct file_ptt_lentry *nentry;

                if ( !is_in ) {
                        /* create hentry first if does not exist */
                        hentry = (struct file_ptt_hentry *)ptt_slab_alloc(ptt->hentry_cache);
                        if (!hentry) {
                                //spin_unlock_irqrestore(&ptt_add_lock, flags);
                                return 0;
                        }
                        hentry->mapping = mapping;
                        hentry->vaddr_list = NULL; 
                        hentry->vaddr_list_len = 0;
                        hentry->access = 0;
                        hentry->touch = 0;
                        hash_add(ptt->htable, &hentry->node, (unsigned long)mapping);

                        ptt->index_table[ptt->hentry_counter++] = hash_min((unsigned long)mapping, HASH_BITS(ptt->htable));

                } else {
                        /* get hentry when exists */
                        hash_for_each_possible(ptt->htable, hentry, node, (unsigned long)mapping) {
                                if (hentry->mapping == mapping) 
                                        break;
                        }
                }
                
                BUG_ON(!hentry);
                hentry->access++;
                //if (!hentry) {
                //        printk("ARC ERROR: no hentry error\n");
                //       spin_unlock_irqrestore(&ptt_add_lock, flags);
                //        return 0;
                //}

                /* CAREFUL INSERTION!! */
                /* Merge extents opportunistically */
                /* Sort extents by start index */
                /* We used 16 for merge spare size */
                /* new lentry add */
                /* Extent demotion limiting the maximum extent size to
                 * PG_SIZE/WORD_SIZE(=512) */
                lentry = hentry->vaddr_list;
                nentry = (struct file_ptt_lentry *)ptt_slab_alloc(ptt->lentry_cache);
                if (!nentry) {
                        //spin_unlock_irqrestore(&ptt_add_lock, flags);
                        return 0;
                }
                /* sort by index */
                nentry->start = start;
                nentry->len = len;
                nentry->next = NULL;
                if (!lentry) {
                        hentry->vaddr_list = nentry;
                        hentry->vaddr_list_len++;
                } else {
                        struct file_ptt_lentry *pentry = NULL;
                        while(lentry) { // Opportunistically merge
                                if (interval_overlapped(lentry->start,
                                                        lentry->len,
                                                        nentry->start,
                                                        nentry->len,
                                                        16)) {
                                        unsigned long new_st;
                                        unsigned long new_len;
                                        merge_interval(lentry->start,
                                                        lentry->len,
                                                        nentry->start,
                                                        nentry->len,
                                                        &new_st,
                                                        &new_len);
                                        lentry->start = new_st;
                                        lentry->len = new_len;
                                        kmem_cache_free(ptt->lentry_cache, nentry);
                                        
                                        // demote extent if needed 
                                        if (lentry->len >= EXT_MAX_SZ) { // extent reaches max size
                                                demote_extent(ptt, lentry);
                                                break;
                                        }
                                        
                                        // recursive merging 
                                        while (lentry->next) {
                                                if (lentry->next->len >= EXT_MAX_SZ) { // next extent reaches max size
                                                        break;
                                                } else if (interval_overlapped(lentry->start,
                                                                        lentry->len,
                                                                        lentry->next->start,
                                                                        lentry->next->len,
                                                                        16)) {
                                                        struct file_ptt_lentry *tmp = lentry->next->next;
                                                        //print_asap("recursive merge");
                                                        merge_interval(lentry->start,
                                                                        lentry->len,
                                                                        lentry->next->start,
                                                                        lentry->next->len,
                                                                        &new_st,
                                                                        &new_len);
                                                        lentry->start = new_st;
                                                        lentry->len = new_len;
                                                        kmem_cache_free(ptt->lentry_cache, lentry->next);
                                                        lentry->next = tmp; 
                                                } else 
                                                        break;
                                        }
                                        break;
                                }
                                lentry = lentry->next;
                        }
                        if (!lentry) { // no overlapping, find your pos!
                                if (hentry->vaddr_list->start > nentry->start) {
                                        nentry->next = hentry->vaddr_list;
                                        hentry->vaddr_list = nentry;
                                } else {
                                        pentry = hentry->vaddr_list;
                                        lentry = hentry->vaddr_list->next;
                                        while (lentry) {
                                                if (lentry->start > nentry->start) {
                                                        nentry->next = lentry;
                                                        pentry->next = nentry;
                                                        break;
                                                }
                                                pentry = lentry;
                                                lentry = lentry->next;
                                        }
                                        if (!lentry) {
                                                nentry->next = NULL;
                                                pentry->next = nentry;
                                        }      
                                }
                                if (nentry->len >= EXT_MAX_SZ)
                                        demote_extent(ptt, nentry);
                                //pentry->next = nentry;
                                hentry->vaddr_list_len++;
                        }
                }
                //} else if (lentry->index > nentry->index) {
                //        nentry->next = lentry;
                //        hentry->vaddr_list = nentry;
                //} else {                                     
                //        struct file_ptt_lentry *pentry = lentry;
                //        lentry = lentry->next;
                //        while (lentry) {
                //                if (lentry->index > nentry->index) {
                //                        nentry->next = lentry;
                //                        pentry->next = nentry;
                //                        break;
                //                }
                //                pentry = lentry;
                //                lentry = lentry->next;
                //        }
                //        if (!lentry) {
                //                nentry->next = NULL;
                //                pentry->next = nentry;
                //        }
                //}
                ptt->sz++; 
                //spin_unlock_irqrestore(&ptt_add_lock, flags);
                return 1; 
        }
        return 0;
}

void file_ptt_dump(struct ptt* ptt) {
        int cursor;
        struct file_ptt_hentry *hentry; 
        struct hlist_node *tmp;
        struct file_ptt_lentry* lentry;

        BUG_ON(ptt->is_anon);
        hash_for_each_safe(ptt->htable, cursor, tmp, hentry, node) {
                unsigned long ino = hentry->mapping->host->i_ino;
                int cnt = 1;
                print_asap("file_ptt_dump; inode number %lu", ino);

                lentry = hentry->vaddr_list;
                while (lentry) {
                        print_asap("file_ptt_dump; %d list entry, st=%lu, len=%lu", cnt++, lentry->start, lentry->len);                
                        lentry = lentry->next;
                }
        }

}

void ptt_freeze(struct ptt *ptt) { ptt->updatable = 0; }
void ptt_unfreeze(struct ptt *ptt){ ptt->updatable = 1; }



/* For internal usage */
/* returns the number of swapped page */
int anon_ptt_fetch_one_item(struct ptt *ptt, pid_t tgid, unsigned long vaddr, int kid) {
        struct vm_area_struct *vma;
        unsigned long flags;
        int ret;
        struct mm_struct *mm; 
        struct task_struct *task;
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;
        if (!switch_target_task) {
                print_asap("error - target task null");
                return 0;
        }
        
        task = find_task_by_vpid(tgid);
        if (task) mm = task->mm;
        else return 0;


        if (!vaddr) return 0;

        /* page table walk */
        pgd = pgd_offset(mm, vaddr);
        if (pgd_none(*pgd)) return 0;

        pud = pud_offset(pgd, vaddr);
        if (pud_none(*pud)) return 0;
        
        pmd = pmd_offset(pud, vaddr);
        if (pmd_none(*pmd)) return 0;

        // page is swapped-out == pte is not none and
        // not present at the same time
        pte = pte_offset_kernel(pmd, vaddr);
        if (pte_none(*pte)) return 0; 
        if (pte_present(*pte)) return 0; // already in !!
  
        vma = find_vma(mm, vaddr); 
        flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_USER | FAULT_FLAG_REMOTE; 
        
        if (unlikely(!vma)) {
                print_asap("VA not exists %lu\n", vaddr);
                return 0;
        }
 
        if (!down_read_trylock(&mm->mmap_sem)) {
retry:
                down_read(&mm->mmap_sem);
        } else {
                /*
                 * The above down_read_trylock() might have succeeded in which
                 * case, we'll have missed the might_sleep() from down_read().
                 */
                might_sleep();
        }

        //Before calling do_swap_page, vmf->vm_mm->mmap_sem must be
        //held as a read sem.
        ret = handle_mm_fault(vma, vaddr, flags); 
        
        if (ret & VM_FAULT_RETRY) {
                /*
                 * Clear FAULT_FLAG_ALLOW_RETRY to avoid any risk of
                 * starvation.
                 */
                if (flags & FAULT_FLAG_ALLOW_RETRY) {
                        flags &= ~FAULT_FLAG_ALLOW_RETRY;
                        flags |= FAULT_FLAG_TRIED;
                        goto retry;
                }
        }
        up_read(&mm->mmap_sem);
     
        spin_lock_irqsave(&anon_feedback_buf_lock, flags);
        anon_feedback_buf_va[anon_feedback_buf_len] = vaddr;
        anon_feedback_buf_tgid[anon_feedback_buf_len++] = tgid;
        spin_unlock_irqrestore(&anon_feedback_buf_lock, flags);
        return 1;
}

extern int __do_page_cache_readahead(struct address_space *mapping, struct file *filp,
			pgoff_t offset, unsigned long nr_to_read,
			unsigned long lookahead_size);

int file_ptt_fetch_one_item(struct ptt *ptt, struct address_space *mapping, struct file_ptt_lentry *vaddr_list, int kid, int touch) {
        struct file_ptt_lentry *lentry = vaddr_list;
        int ret = 0, idx, last_node_touch;
       
        if (!lentry) {
                return 0;
        }
       
        if (touch) {
                last_node_touch = -1;
        }

        print_asap("fetch %lu %lu", mapping->host->i_ino, lentry->start);



        while (lentry) {
                if (lentry->len == 0)
                       goto next; 
                
                if (touch) {
                        if (last_node_touch < lentry->start) {
                                ret += __do_page_cache_readahead(mapping, NULL, lentry->start, 1, 0);
                                while (last_node_touch <= lentry->start)
                                        last_node_touch += 512; 
                        }
                } else {
                        if (iorap_mode) {
                                for (idx = 0; idx < lentry->len; idx++) 
                                        ret += __do_page_cache_readahead(mapping, NULL, lentry->start + idx, 1, 0);
                        }
                        else
                                ret += __do_page_cache_readahead(mapping, NULL, lentry->start, lentry->len, 0);
                }
next:
                lentry = lentry->next;
        }

        return ret;
}


DEFINE_SPINLOCK(anon_ptt_fetch_lock);
int anon_ptt_fetch_one_unit(struct ptt *ptt, int kid){
        unsigned int unit_start_idx;  
        unsigned int unit_end_idx;
        unsigned int idx;
        int ret = 0; 
        unsigned long flags;
        struct anon_ptt_hentry *hentry;
        
        if (ptt->fetch_idx >= (1 << PTT_HASH_BITS)) // fetch done!
                return -1;

        if (ptt->updatable) {
                print_asap("error - ptt must be frozen when we fetch items from it");
                return -1; 
        }

        spin_lock_irqsave(&anon_ptt_fetch_lock, flags);
        unit_start_idx = ptt->fetch_idx;
        ptt->fetch_idx += ptt->fetch_unit;
        spin_unlock_irqrestore(&anon_ptt_fetch_lock, flags);

        for (idx = unit_start_idx, unit_end_idx = unit_start_idx + ptt->fetch_unit;
                idx < unit_end_idx && idx < (1 << PTT_HASH_BITS); 
                idx++) {
                hlist_for_each_entry(hentry, &(ptt->htable[idx]), node) {
                        ret += anon_ptt_fetch_one_item(ptt, hentry->tgid, hentry->vaddr, kid);
                }

        }

        return ret;
}

DEFINE_SPINLOCK(file_ptt_fetch_lock);
int file_ptt_fetch_one_unit(struct ptt *ptt, int kid, int touch){
        unsigned int unit_start_idx;  
        unsigned int unit_end_idx;
        unsigned int idx;
        int ret = 0; 
        unsigned long flags;
        struct file_ptt_hentry *hentry;
        
        BUG_ON(ptt->is_anon);
        
        if (ptt->fetch_idx >= (1 << PTT_HASH_BITS)) // fetch done!
                return -1;

        if (ptt->updatable) {
                print_asap("error - ptt must be frozen when we fetch items from it");
                return -1; 
        }
        spin_lock_irqsave(&file_ptt_fetch_lock, flags);
        //if (ptt->index_table[ptt->fetch_idx] == -1) {
        //        spin_unlock_irqrestore(&file_ptt_fetch_lock, flags);
        //        return -1;
        //} 

        unit_start_idx = ptt->fetch_idx;
        ptt->fetch_idx += ptt->fetch_unit;
        spin_unlock_irqrestore(&file_ptt_fetch_lock, flags);


        
        for (idx = unit_start_idx, unit_end_idx = unit_start_idx + ptt->fetch_unit;
                idx < unit_end_idx && idx < (1 << PTT_HASH_BITS); 
                idx++) {
                //int htable_idx = ptt->index_table[idx];
                hlist_for_each_entry(hentry, &(ptt->htable[idx]), node) {
                        ret += file_ptt_fetch_one_item(ptt, hentry->mapping, hentry->vaddr_list, kid, touch);
                }
        }

        return ret;
}





int ptt_fetch_one_unit(struct ptt *ptt, int kid){
        int ret;
        if (ptt->is_anon) {
                ret = anon_ptt_fetch_one_unit(ptt, kid);
        } else { 
                ret = file_ptt_fetch_one_unit(ptt, kid, 0);
        }

       return ret;
}


void file_ptt_touch(struct ptt *ptt) {
        int cursor;
        struct file_ptt_hentry *hentry; 

        BUG_ON(ptt->is_anon);
        hash_for_each(ptt->htable, cursor, hentry, node) {
                if (hentry->access > 0) {
                       hentry->access = 0;
                       hentry->touch++;
                }
        }
}

// shadow API
// add
// del
// is_in 
// key = mapping + index


void file_shadow_init(struct shadow *shadow, bool is_anon) {
        shadow->is_anon = is_anon;
        shadow->sz = 0;
        hash_init(shadow->htable);
}

bool file_shadow_is_in(struct shadow *shadow, struct address_space *mapping, unsigned long index) {
        struct file_shadow_hentry *hentry;
        
        hash_for_each_possible(shadow->htable, hentry, node, (unsigned long)mapping + index) {
                if (hentry->mapping == mapping && hentry->index == index)
                        return 1;
        }
        return 0;       
}



void file_shadow_add(struct shadow *shadow, struct address_space *mapping, unsigned long index) {
        struct file_shadow_hentry *hentry;
        
        if (!file_shadow_is_in(shadow, mapping, index)) {
                struct file_shadow_hentry *hentry = kmem_cache_alloc(file_shadow_cache, GFP_KERNEL);
                hentry->mapping = mapping;
                hentry->index = index;
                hentry->cnt = 1;
                hash_add(shadow->htable, &hentry->node, (unsigned long)mapping + index);
                shadow->sz++;
        } else {
                hash_for_each_possible(shadow->htable, hentry, node, (unsigned long)mapping + index) {
                        if (hentry->mapping == mapping && hentry->index == index) {
                                hentry->cnt++;       
                                return;
                        }
                }
        }
}
void file_shadow_del(struct shadow *shadow, struct address_space *mapping, unsigned long index) {
         struct file_shadow_hentry *hentry;
        
        hash_for_each_possible(shadow->htable, hentry, node, (unsigned long)mapping + index) {
                if (hentry->mapping == mapping && hentry->index == index) {
                        hash_del(&hentry->node);
                        kmem_cache_free(file_shadow_cache, hentry);
                        shadow->sz--;
                        return;
                }
        }
}
void file_shadow_clear(struct shadow *shadow) {
        int cursor;
        struct file_shadow_hentry *hentry; 
        hash_for_each(shadow->htable, cursor, hentry, node) {
                hash_del(&(hentry->node));        
                kmem_cache_free(file_shadow_cache, hentry);                
        }
        hash_init(shadow->htable);
        shadow->sz = 0;
}

void apg_init(struct apg *apg) {
        hash_init(apg->htable);
}

bool apg_is_in(struct apg *apg, pid_t tgid) {
        struct apg_hentry *hentry;
        
        hash_for_each_possible(apg->htable, hentry, node, tgid) {
                if (hentry->tgid == tgid)
                        return 1;
        }
        return 0; 
}

void apg_add(struct apg *apg, pid_t tgid) {
        struct apg_hentry *hentry;
        if (!apg_is_in(apg, tgid)) {
                hentry =  (struct apg_hentry *)vmalloc(sizeof(struct apg_hentry));
                hentry->tgid = tgid;
                hentry->cnt = 1;
                hash_add(apg->htable, &hentry->node, tgid);
        } else { 
                hash_for_each_possible(apg->htable, hentry, node, tgid) {
                        if (hentry->tgid == tgid)
                                hentry->cnt++;
                }
        }
}

void apg_del(struct apg *apg, pid_t tgid) {
        struct apg_hentry *hentry;
        if (apg_is_in(apg, tgid)) {
                hash_for_each_possible(apg->htable, hentry, node, tgid) {
                        if (hentry->tgid == tgid) {
                                hash_del(&hentry->node);
                                vfree(hentry);
                                return;
                        }
                }
        }
}

void file_ptt_report_stat(struct ptt *ptt) {
        struct file_ptt_hentry *hentry;
        int cursor;
        int extent_num = 0;
        int page_num = 0;
        hash_for_each(ptt->htable, cursor, hentry, node) {
                struct file_ptt_lentry *lentry = hentry->vaddr_list;
                while(lentry) {
                        extent_num++;
                        page_num += lentry->len;        
                        lentry =  lentry->next;
                }
        }
        print_asap("SWS size report: extens %d / covered pages %d", extent_num, page_num);
}



static int __init ptt_ginit(void)
{
//        /* ptt init */
        file_shadow_cache = kmem_cache_create("file_shadow_cache",
                        sizeof(struct file_shadow_hentry),
                        0,
                        0,
                        NULL);        

        return 0;
}

module_init(ptt_ginit)




#endif /* ENABLE_ASAP */
