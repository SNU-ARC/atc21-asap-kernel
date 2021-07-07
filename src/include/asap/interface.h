/* ARC_SNU ASAP
 * interface.h
 * main header of the project
 * Author: Sam Son(sosson97@gmail.com)
 * */
#ifndef _ARC_INTERFACE_H
#define _ARC_INTERFACE_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/printk.h>
#include <linux/compiler.h>
#include <linux/mm_types.h>
#include <linux/wait.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <linux/fs.h>
#include <asm/page.h>

/* ASAP compiler option */
#define ENABLE_ASAP


#define print_asap(fmt, ...) printk("%s:%s%d:%s: " fmt, "ASAP_INFO", "CPU", smp_processor_id(),current->comm, ## __VA_ARGS__)



#ifdef ENABLE_ASAP
/* Global switch flag
 * The flag is set when the device is in application switch.
 * */
extern atomic_t global_switch_flag;


/* Counters  
 * Counters used to calculate precision/recall of SFE
 */
extern atomic_t swap_in_called_cnt;
extern atomic_t anon_app_hit_cnt;
extern atomic_t read_pages_cnt;
extern atomic_t apg_read_pages_cnt;


/* CPU configuration
 * This should be set manually. # of little cores is unknown to kernel
 * We used Pixel 4 with Snapdragon 855 which is an octa-core SoC.
 * 4 of cores are big, and the others are LITTLE
 */
#define ASAP_CORE_NUM 8
#define ASAP_LITTLE_CORE_NUM 4


/* Prepaging threads and
 * data structures managing them
 * */

/* two prepaaging threads are assigned to each core.
 * One for anon preapging, and the other for file prepaging.
 * */
#define PPTHREAD_NUM ASAP_CORE_NUM*2

/* Pointer to task_struct of currently switching app process.
 * This is used for VM manipulation(e.g. PTE access, raising PF)
 * This is set via procfs by Android ActivityManager.
 * */
extern struct task_struct *switch_target_task;

/* an index of switching app process within app table */
extern int switch_target_idx;

/* prepaging threads */
extern struct task_struct *ppthreads[PPTHREAD_NUM];
extern int ppthreads_stat[PPTHREAD_NUM];

/* auxiliary data sturctures used to wake up or make threads sleep */
extern atomic_t kid_work[PPTHREAD_NUM];
extern struct wait_queue_head anon_ppthreads_wq;

/* ASAP maintains redundant wait queues for each core to support file-related core scheduling */
extern struct wait_queue_head file_ppthreads_wqs[ASAP_CORE_NUM];
extern struct wait_queue_head node_ppthreads_wq;
extern pid_t ppthread_min_pid, ppthread_max_pid;



/* PER-APP TABLE
 * app_{data name}_table
 * Use table_name[switch_target_idx] to get data of currently switching app 
*  list of per-app tables
 * name = name of an application in plain string --> invariant over boots
 * uid = uid of an application --> invaraint over boots(manually tyepd for experiment)
 * pid = pid of an app process if it exists
 * ptt = prepaging target table
 * ct = candidte table
 * big_file_ptt = special ptt storing pages of files larger than 10MB
 *
 * shadow/apg --> auxilary data structures used in offline profiling
 * */
#define MAX_APP_NUM 256
extern const char *app_name_table[MAX_APP_NUM];
extern int app_uid_table[MAX_APP_NUM];
extern int app_pid_table[MAX_APP_NUM];
extern struct ptt * app_big_file_ptt_table[MAX_APP_NUM];
extern struct ptt * app_file_ptt_table[MAX_APP_NUM];
extern struct ptt * app_file_ct_table[MAX_APP_NUM];
extern struct shadow *app_file_shadow_table[MAX_APP_NUM]; 
extern struct apg *app_apg_table[MAX_APP_NUM]; 
extern struct anon_table *app_anon_table[MAX_APP_NUM];

/* procfs entries
 * procfs is used for several purposes
 * 1. Android notifies switch start/end timing via procfs
 * 2. Some experimental variables are configured via procfs
 * 3. Some timing information(e.g. end of offline profiling) is given manually via procfs
 * */

// timing-related entries
extern int app_switch_start;
extern int app_switch_end;
extern int app_switch_start_filter;
extern pid_t switch_target_pid; 

// experiment options
extern int file_prepaging; // 0(disable) or 1(enable)
extern int anon_prepaging; // 0(disable) or 1(enable)
extern int open_one_core; // change # of cores utilized for prepaging
extern int core_scheduling_policy; // change core scheduling policy
extern int clear_anonlist; // clear anon ct and ptt
extern unsigned int default_tick; // set timeout_tick 
extern int file_ptt_print; // print all file-backed pages of a process
extern int anon_page_dump; // dump info of all anonymous pages of process
extern int anon_page_dump_clear_af; // clear access-bit of all anonymous pages of a process
extern int anon_page_swap; // swap all anonymous pages of a process

// obsoleted
extern int app_launch_start_filter; // obsolete
extern int trace_filter; // obsolete
extern int cur_ppthreads_num; // obsolete
extern int hot_evict_num; // obsolete 
extern int debug_file_fetch; // obsolete
extern int system_server_pid; // obsolete
extern int iorap_core; // obsolete
extern int iorap_mode; // obsolete
extern int freeze_ptt; // don't use this!


/* Offline Profiling 
 * The goal of offline profiling is to capture a static working set of file-backed pages.
 * */
#define MAX_APP_NAME_LEN 256
extern int on_launch_profile;
extern char launch_profile_start_target[MAX_APP_NAME_LEN];
extern char launch_profile_end_target[MAX_APP_NAME_LEN];
extern char file_ptt_gen_target[MAX_APP_NAME_LEN];
extern int file_ptt_gen_threshold; // pages accessed more than this TH will be inserted to CT 


/* Core scheduling
 * a core scheduling policy determines cores that participate in prepaging process.
 * To be specific, it changes
 * 1. Number of cores
 * 2. Type of cores(big,LITTLE)
 * */
extern int *core_schedule_arr; // represents the current core scheduling policy

/* procfs handler prototype */
int do_nothing_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int app_switch_start_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int app_switch_end_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int app_switch_start_filter_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int app_launch_start_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int switch_target_pid_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int perf_test_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int cur_ppthreads_num_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int hot_evict_num_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int swap_in_cnt_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int debug_file_fetch_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int trace_filter_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int file_prefetch_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int anon_prefetch_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int system_server_pid_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int anon_page_dump_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int anon_page_swap_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos);
int launch_profile_start_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int launch_profile_end_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int file_ptt_gen_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
void _launch_profile_start(void);
void _launch_profile_end(void);
void _file_ptt_gen(void);
int iorap_mode_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int apg_profile_start_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int apg_profile_end_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int apg_gen_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
void _apg_profile_start(void);
void _apg_profile_end(void);
int file_ptt_dump_sysctl_handler(struct ctl_table *, int,
                    void __user *, size_t *, loff_t *);
int clear_anonlist_sysctl_handler(struct ctl_table *table, int write, 
                void __user *buffer, size_t *length, loff_t *ppos);
int default_tick_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos);
int open_one_core_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos);
/* prototyped ends */

/* APG(Application Process Group)
 * APG is a list of processes used together when an app comes FG.
 * APG is collected in offline profiling.
 * */
#define APG_HASH_BITS 3
struct apg {
        DECLARE_HASHTABLE(htable, APG_HASH_BITS);
};
extern int apg_profile_filter;
extern char apg_profile_start_target[MAX_APP_NAME_LEN];
extern int apg_profile_end;

/* APG API */
void apg_init(struct apg *apg);
bool apg_is_in(struct apg *apg, pid_t tgid);
void apg_add(struct apg *apg, pid_t tgid);
void apg_del(struct apg *apg, pid_t tgid);



/* Prepaging Target Table(ptt) 
 * a table storing prepaging target pages
 * prepaging threads fetch all pages in this table at the beginning of app switching
 * NOTE: This struct is also used for Candidate table since two tables have same layout
 * */
#define PTT_HASH_BITS 7
#define PTT_INDEX_TB_BITS 10
struct ptt {
        /* index of lastly fetched page */
        unsigned int fetch_idx;

        /* fetching batch size */
        unsigned int fetch_unit;

        unsigned long sz; 

        /* hash table storing target page information */
        DECLARE_HASHTABLE(htable, PTT_HASH_BITS);
        int index_table[(1 << PTT_INDEX_TB_BITS)];
        int hentry_counter;
        
        /* add/remove is possible only when updatable=1 */
        bool updatable;

        spinlock_t lock;
        bool is_anon; // true: anon ptt, false: file ptt

        /* slab allocators for hash entries */
        struct kmem_cache *hentry_cache;
        struct kmem_cache *lentry_cache;
};


/* we integrated ptt and ct of anon pages into one struct for the ease of implementation */
struct anon_table{
        struct ptt *ptt;
        struct ptt *ct;
        struct kmem_cache *hentry_cache;
        unsigned int start_tick;
};
extern struct anon_table *current_anon_table;


/* Prepaging Target Table(ptt) API 
 * ptts for anon and file pages have different API and implementation
 * 
 * */
void anon_table_init(struct anon_table *ant);

int anon_ptt_add(struct ptt *ptt, pid_t tgid, unsigned long vaddr);
bool anon_ptt_is_in(struct ptt *ptt, pid_t tgid, unsigned long vaddr);
void anon_ptt_clear(struct ptt *ptt);
int anon_ptt_clearaccess(struct ptt *ptt);

/* decrement timeout counter and  update ptt(or ct) based on timeout counter and access info 
 * promotion if page was accessed at this switch 
 * eviction if timeout counter reaches 0
 * */
void anon_ptt_sweep(struct ptt *ptt, bool isct);

void ptt_init(struct ptt *ptt, unsigned int unit, bool is_anon);

void file_ptt_clear(struct ptt *ptt);

/* check if a file of a given extent exists in ptt */
int file_ptt_is_in(struct ptt *ptt,
                struct address_space *mapping, 
                unsigned long start, unsigned long len);

/* check if a given extent overlaps with any extent in ptt */
int file_ptt_is_in_detail(struct ptt *ptt,
                struct address_space *mapping, 
                unsigned long start, unsigned long len);

/* delete one page from ptt 
 * if the page belongs to one page extent --> delete extent 
 * if the page is in the middle of long extent --> delete page and split the extents into two
 * */
int file_ptt_del(struct ptt *ptt, 
                struct address_space *mapping, 
                unsigned long idx);

/* add one extent to ptt 
 * If there exists an overlapped extent with the input extent, they should be merged
 * This merging makes this function excessively lengthy
 * */
int file_ptt_add(struct ptt *ptt, 
                struct address_space *mapping, 
                unsigned long start, unsigned long len);

void file_ptt_dump(struct ptt *ptt);

/* see ptt_fetch_one_unit() */
int file_ptt_fetch_one_unit(struct ptt *ptt, int kid, int touch);

/* These two functions are used in offline profiling 
 * In offline profiling, every accessed page is recorded one by one,
 * and they are compacted to extents at the end of the profiling
 * */
int file_ptt_add_one(struct ptt *ptt, 
                struct address_space *mapping, 
                unsigned long index,
                int unit);  
void file_ptt_compact(struct ptt *ptt, int spare);

/* fetch one batch in ptt
 * This is fetching function prepaging threads use.
 * A batch is taken from the location pointed by fetch_idx.
 * fetch_idx is automatically adjusted in this function
 * */
int ptt_fetch_one_unit(struct ptt *ptt, int kid);
void ptt_freeze(struct ptt *ptt);
void ptt_unfreeze(struct ptt *ptt);


void file_ptt_report_stat(struct ptt *ptt);


/* shadow table
 * shadow is a table recording accessed pages during offline profiling
 * _file_page_gen() function generates a candidate table for an app from shadow table 
 * */
#define SHADOW_HASH_BITS 10
struct shadow {
        unsigned long sz;
        bool is_anon;
        DECLARE_HASHTABLE(htable, SHADOW_HASH_BITS);
};

/* Fault Buffer 
 * a fault buffer records a page info which is the target of page fault or file read/write.
 * */
#define FAULT_BUF_SZ 65536
struct anon_fault_buf_entry {
        unsigned long tgid;
        unsigned long va;
}
extern anon_fault_buf_entry anon_fault_buf[FAULT_BUF_SZ];
extern unsigned int anon_fault_buf_len;

struct file_fault_buf_entry {
        unsigned long mapping; 
        unsigned long start;
        unsigned long len;
}
extern file_fault_buf_entry file_fault_buf[FAULT_BUF_SZ];
extern unsigned int file_fault_buf_len;

/* pointer to current app's table*/
extern struct ptt *current_file_ptt;
extern struct ptt *current_big_file_ptt;
extern struct ptt *current_file_ct;
extern struct ptt *current_anon_ptt;

/* file_shadow API 
 * shadow is a table recording  pages accessed during offline profiling
 * _file_page_gen() function generates a candidate table for an app from shadow table 
 * */
void file_shadow_init(struct shadow *shadow, bool is_anon);
bool file_shadow_is_in(struct shadow *shadow, struct address_space *mapping, unsigned long index);
void file_shadow_add(struct shadow *shadow, struct address_space *mapping, unsigned long index);
void file_shadow_del(struct shadow *shadow, struct address_space *mapping, unsigned long index);
void file_shadow_clear(struct shadow *shadow);



/* Buffers for ppt feedback 
 * these buffers records pages prepaged by prepaging threads.
 * If a page in this buffer tunrs out to be not accessed by app, it is evicted from ptt.
 * */
extern unsigned long anon_feedback_buf_va[FAULT_BUF_SZ];
extern pid_t anon_feedback_buf_tgid[FAULT_BUF_SZ];
extern unsigned int anon_feedback_buf_len;

extern struct address_space *file_feedback_buf_mapping[FAULT_BUF_SZ];
extern int file_feedback_buf_idx[FAULT_BUF_SZ];
extern int file_feedback_buf_len;



static inline bool is_current_ppthread() {
        return (current->pid >= ppthread_min_pid && current->pid <= ppthread_max_pid);
}

static inline loff_t mapping_host_size(struct address_space *mapping) {
        return i_size_read(mapping->host);
}


#endif /* ENABLE_ASAP */

#endif /* _ARC_INTERFACE_H */
