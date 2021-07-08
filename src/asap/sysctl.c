/* SNU ARC Lab. ASAP */
/* sysctl.c 
 * control functions of ASAP 
 * 1. procfs handler
 * 2. table updates
 * 3. cleaning buffer 
 * */

#include <asap/interface.h>
#include <asap/available_list.h>
#include <linux/sysctl.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/fdtable.h>
#include <linux/pagemap.h>
#include <uapi/linux/sched/types.h>

#ifdef ENABLE_ASAP
int app_switch_start;
int app_switch_end;
int app_switch_start_filter;
pid_t switch_target_pid; 
int cur_ppthreads_num;

atomic_t global_switch_flag;
atomic_t swap_in_called_cnt;
atomic_t anon_app_hit_cnt;
atomic_t read_pages_cnt;
atomic_t apg_read_pages_cnt;
int hot_evict_num;
int debug_file_fetch;
int trace_filter;

int file_prepaging;
int anon_prepaging;
int system_server_pid;
int iorap_mode;
int clear_anonlist;
int freeze_ptt;


int on_launch_profile;
char launch_profile_start_target[MAX_APP_NAME_LEN];
char launch_profile_end_target[MAX_APP_NAME_LEN];
char file_ptt_gen_target[MAX_APP_NAME_LEN];
int file_ptt_gen_threshold;

//app table
const char *app_name_table[MAX_APP_NUM];
int app_uid_table[MAX_APP_NUM];
int app_pid_table[MAX_APP_NUM];
struct ptt * app_big_file_ptt_table[MAX_APP_NUM];
struct ptt * app_file_ptt_table[MAX_APP_NUM];
struct ptt * app_all_file_ptt_table[MAX_APP_NUM];
struct shadow *app_file_shadow_table[MAX_APP_NUM]; 
struct apg *app_apg_table[MAX_APP_NUM]; 
struct anon_table *app_anon_table[MAX_APP_NUM];


int apg_profile_filter;
char apg_profile_start_target[MAX_APP_NAME_LEN];
int apg_profile_end;



// core schedule policy
int core_scheduling_policy;
int *core_schedule_arr;

// ex policies
static int core_schedule_arr_ours[ASAP_CORE_NUM] = {4, 0, 1, 2, 3, 5, 6, 7};
static int core_schedule_arr_bigonly[ASAP_CORE_NUM] = {4, 5, 6, 7, 0, 1, 2, 3};
static int core_schedule_arr_smallonly[ASAP_CORE_NUM] = {0, 1, 2, 3, 4, 5, 6, 7};

static void scan_n_fill_history(void) {
        int idx;
        struct mm_struct *mm; // = switch_target_task->mm;
        unsigned int cnt = anon_feedback_buf_len, hit = 0, miss = 0, unknown;// del = 0;
        int app_hit = 0;
        
        print_asap("scan start | total cnt %ld", cnt);

        for (idx = 0; idx < anon_feedback_buf_len; idx++) { 
                pgd_t *pgd;
                pud_t *pud;
                pmd_t *pmd;
                pte_t *pte; 
                pid_t tgid = anon_feedback_buf_tgid[idx];
                unsigned long vaddr = anon_feedback_buf_va[idx];
                struct task_struct *task = find_task_by_vpid(tgid);

                if (!vaddr || !task) {
                        print_asap("no task tgid:%lu", tgid);
                        continue;
                }
                mm = task->mm;
                // page table walk
                pgd = pgd_offset(mm, vaddr);
                if (pgd_none(*pgd)) continue;

                pud = pud_offset(pgd, vaddr);
                if (pud_none(*pud)) continue;
                
                pmd = pmd_offset(pud, vaddr);
                if (pmd_none(*pmd)) continue;
    
                pte = pte_offset_kernel(pmd, vaddr);
                if (!pte || pte_none(*pte)) continue;
               
                if (pte_young(*pte)) {                        
                        hit += 1;
                        continue;
                }
                
                miss += 1;
        }

        unknown = cnt - hit - miss;
        app_hit = atomic_read(&anon_app_hit_cnt);
        print_asap("ANON PREPAGING STAT, %ld, %ld, %ld, %d", hit, miss, atomic_read(&swap_in_called_cnt) - unknown, app_hit);

        anon_feedback_buf_len = 0;
}

static void file_scan_n_drop_pages(void) {
        int idx;
        struct address_space *mapping;
        int pgoff;
        struct page *page;
        int cnt = 0, cnt2 = 0;
        struct ptt *ptt;
        int apg_cnt;
        int read_cnt;
        for (idx = 0; idx < file_feedback_buf_len; idx++) {
                mapping = file_feedback_buf_mapping[idx];
                pgoff = file_feedback_buf_idx[idx];
                ptt = mapping_host_size(mapping) > 4 * 1024 * 1024 ? current_big_file_ptt : current_file_ptt; 
		
                rcu_read_lock();
		page = radix_tree_lookup(&mapping->page_tree, pgoff);
		rcu_read_unlock();
                
                if (!page || radix_tree_exceptional_entry(page))
			continue;
                
                if (page_mapcount(page) == 0) {
                        cnt += file_ptt_del(ptt, mapping, pgoff);
                        cnt2++;
                }
        }

        print_asap("scan_n_drop %d, %d / %d pages\n", cnt, cnt2, file_feedback_buf_len);
        
        apg_cnt =  atomic_read(&apg_read_pages_cnt);
        read_cnt = atomic_read(&read_pages_cnt);
        print_asap("FILE PREPAGING STAT, %d, %d, %d, %d", cnt, file_feedback_buf_len - cnt, apg_cnt, read_cnt);
        file_feedback_buf_len = 0;
}

static void _file_page_dump(pid_t pid, bool clear, bool add) {
        struct task_struct *task = find_task_by_vpid(pid);
        unsigned long vpage;
        int accessed, idx;
        struct vm_area_struct *vma;
        int cnt = 0, access_cnt = 0;
        struct address_space *mapping;
        if (!task) {
                print_asap("task %d not found", pid); 
                return;
        }
        print_asap("file page dump; start");
        if (task->mm && task->mm->mmap) {
                for (vma = task->mm->mmap; vma; vma = vma->vm_next) {
                        if (!vma->vm_file) 
                                continue;

                                
                        mapping = vma->vm_file->f_mapping;

                        if (!mapping->a_ops->readpages)
                                continue;
                        for (vpage = vma->vm_start, idx = 0; vpage < vma->vm_end; vpage += PAGE_SIZE, idx++) {
                                pgd_t *pgd;
                                pud_t *pud;
                                pmd_t *pmd;
                                pte_t *pte;
                                pte_t entry;
                                struct mm_struct *mm = task->mm;
                        
                                // page table walk
                                pgd = pgd_offset(mm, vpage);
                                if (pgd_none(*pgd)) continue;

                                pud = pud_offset(pgd, vpage);
                                if (pud_none(*pud)) continue;
                        
                                pmd = pmd_offset(pud, vpage);
                                if (pmd_none(*pmd)) continue;
            
                                pte = pte_offset_kernel(pmd, vpage);
                                if (!pte || pte_none(*pte)) continue;
                                
                                if (pte_present(*pte)) {
                                        accessed = pte_young(*pte);
                                        if (clear) {
                                                entry = pte_mkold(*pte); 
	                                        set_pte_at(mm, vpage, pte, entry);
                                        }
                                }
                                else
                                        accessed = 2; //swapped!
                                
                                if ( add && accessed == 1 ) {
                                        unsigned long index = linear_page_index(vma, vpage);
                                        file_shadow_add(app_file_shadow_table[switch_target_idx], mapping, index);   
                                }
                                if (accessed == 1) access_cnt++; 
                                
                                cnt++;
                        }
                }
        }
        print_asap("file page dump; end; cnt=%d, acnt=%d", cnt, access_cnt);
}



/* handlers */
int app_switch_start_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write && app_switch_start_filter) { 
                int kid;
                int nr_cleared;
                
                atomic_set(&swap_in_called_cnt, 0);
                atomic_set(&anon_app_hit_cnt, 0);
                atomic_set(&read_pages_cnt, 0);
                atomic_set(&apg_read_pages_cnt, 0);
                
                atomic_set(&global_switch_flag, 1); 
                if(!freeze_ptt && anon_prepaging){
                        print_asap("anon_ptt_clearaccess_main start %ld\n", current_anon_ptt->sz);
                        nr_cleared = anon_ptt_clearaccess(current_anon_ptt);
                        print_asap("anon_ptt_clearaccess_main end cleared %d\n", nr_cleared);

                        print_asap("anon_ptt_clearaccess_shadow start %ld\n", current_anon_table->ct->sz);
                        nr_cleared = anon_ptt_clearaccess(current_anon_table->ct);
                        print_asap("anon_ptt_clearaccess_shadow end cleared %d\n", nr_cleared);
                }
                
                /* now ready to wake up ppthreads */
                if (!iorap_mode) {
                        for (kid = 0; kid < ASAP_CORE_NUM; kid++) {
                                ppthreads_stat[kid] = 0;
                                atomic_set(&kid_work[kid], 1);
                        }
                }
                for (kid = ASAP_CORE_NUM; kid < ASAP_CORE_NUM; kid++) { 
                        ppthreads_stat[kid] = 0;
                        atomic_set(&kid_work[kid], 1);
                }
               
                if (file_prepaging) {
                        int idx;
                        /* node_ppthreads  */
                        if (!iorap_mode) { // node_ppthreads not supported in iorap mode
                                print_asap("wake up node_ppthreads!");
                                wake_up_interruptible_all(&node_ppthreads_wq);
                                for (idx = 0; idx < ASAP_CORE_NUM; idx++) {
                                        print_asap("node_ppthreads %d wait", idx);
                                        for ( ; ; ) {
                                                //print_asap("kid_work[%d] = %d", idx, atomic_read(&kid_work[idx]));
                                                if (!atomic_read(&kid_work[idx])) { 
                                                        atomic_set(&kid_work[idx], 1);
                                                        break;
                                                }
                                        }
                                        print_asap("node_ppthreads %d done", idx);
                                }
                        }
                        print_asap("node_ppthreads done");
                        current_file_ptt->fetch_idx = 0;
                        current_big_file_ptt->fetch_idx = 0;

                        /* file ppthreads */
                        // wake up threads
                        if (iorap_mode) {
                                wake_up_interruptible_all(&file_ppthreads_wqs[iorap_core]);
                        } else {
                                if ( core_scheduling_policy == 0 ) {
                                        core_schedule_arr = core_schedule_arr_ours;
                                } else if ( core_scheduling_policy == 1) {
                                        core_schedule_arr = core_schedule_arr_bigonly;
                                } else if ( core_scheduling_policy == 2) {
                                        core_schedule_arr = core_schedule_arr_smallonly;
                                } else {
                                        print_asap("invalid core scheduling policy - %d", core_scheduling_policy);
                                }
                                 
                                //for (idx = 0; idx < app_curr_thread_num_table[switch_target_idx]; idx++)
                                for (idx = 0; idx < open_one_core; idx++)
                                        wake_up_interruptible_all(&file_ppthreads_wqs[core_schedule_arr[idx]]);
                                //for (idx = app_curr_thread_num_table[switch_target_idx]; idx < ASAP_CORE_NUM; idx++)

                                for (idx = open_one_core; idx < ASAP_CORE_NUM; idx++)
                                        atomic_set(&kid_work[ASAP_CORE_NUM + (ASAP_CORE_NUM - 1 - core_schedule_arr[idx])], 0);
                        }
                }
                if (anon_prepaging && !iorap_mode)
                        wake_up_interruptible_all(&anon_ppthreads_wq);
                
                        
                anon_fault_buf_len = 0;
                file_fault_buf_len = 0;
                
                print_asap("ppthreadss in wait queue woken up.\n");
                
                schedule();
                
        }

        print_asap("start finish");
	return 0;
}


int app_switch_end_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
		int prefetch_cnt = 0;
                int idx;
               
                /* check ppthreads done */
                print_asap("check ppthreads running");
               


                if (anon_prepaging) {
                        for (idx = 0; idx < ASAP_CORE_NUM; idx++) {
                                for ( ; ; ) {
                                        if (!atomic_read(&kid_work[idx]))
                                                break;
                                }
                        }
                }

                if (file_prepaging) {
                        for (idx = ASAP_CORE_NUM; idx < ASAP_CORE_NUM; idx++) {
                                for ( ; ; ) {
                                        if (!atomic_read(&kid_work[idx]))
                                                break;
                                }
                        }
                }


                atomic_set(&global_switch_flag, 0); 
                // anon access bit check
                if (current_anon_ptt && anon_prepaging) {
                        // (1) anon update
                        ptt_unfreeze(current_anon_ptt);
                        ptt_unfreeze(current_anon_table->ct);
                        
                        print_asap("anon ptt access sweep start\n");
                        if(!freeze_ptt){
                                anon_ptt_sweep(current_anon_ptt, 0);
                                anon_ptt_sweep(current_anon_table->ct, 1);
                                print_asap("anon_fault_buf_len %lu\n", anon_fault_buf_len);
                                for (idx = 0; idx < anon_fault_buf_len; idx++) { 
                                        anon_ptt_add(current_anon_table->ct, anon_fault_buf[idx].tgid, anon_fault_buf[idx].va);
                                }
                        }
                        print_asap("anon ptt access sweep end\n");

                        anon_fault_buf_len = 0;
                        current_anon_ptt->fetch_idx = 0;

                        ptt_freeze(current_anon_ptt);
                        ptt_freeze(current_anon_table->ct);
                }

                // file mapcount check 
                if (file_prepaging)
                        file_scan_n_drop_pages();
                              
                // stat report
                for (idx = 0; idx < ASAP_CORE_NUM; idx++)
                        prefetch_cnt += ppthreads_stat[idx];
                print_asap("SwapPrefetch Stat");
                print_asap("swap-in cnt: %d\n", swap_in_called_cnt.counter);
                print_asap("prefetch cnt: %d\n", prefetch_cnt);
                if (current_anon_ptt && anon_prepaging) {        
                        print_asap("anon shadow ptt sz: %ld\n", current_anon_table->ct->sz);
                        print_asap("anon ptt sz: %ld\n", current_anon_ptt->sz);
                        scan_n_fill_history(); 
                }

       
                        
                        
                print_asap("checking done");


                // file update
                if ( file_prepaging && current_file_ptt ) { 
                        // new member add
                        ptt_unfreeze(current_file_ptt);
                        ptt_unfreeze(current_big_file_ptt);
                        for (idx = 0; idx < file_fault_buf_len; idx++)  {      
                                struct address_space *mapping = (struct address_space*)file_fault_buf[idx].mapping;
                                unsigned long start = file_fault_buf[idx].start;
                                unsigned long len = file_fault_buf[idx].len;

                                if ( !file_ptt_is_in_detail(current_file_ct, mapping, start, len) ) {
                                        continue;
                                }
                                
                                if (mapping_host_size(
                                        (struct address_space *)file_fault_buf[idx].mapping
                                        ) > 4 * 1024 * 1024) {
                                        file_ptt_add(current_big_file_ptt,
                                                        mapping,
                                                        start,
                                                        len);
                                        continue;
                                }
                                        
                                file_ptt_add(current_file_ptt,
                                                mapping,
                                                start,
                                                len);
                        }
                        file_fault_buf_len = 0;
                        current_file_ptt->fetch_idx = 0;
                        current_big_file_ptt->fetch_idx = 0;
                       
                        print_asap("file_ptt overhead report");
                        file_ptt_report_stat(current_file_ptt);
                        file_ptt_report_stat(current_big_file_ptt);

                        ptt_freeze(current_file_ptt);
                        ptt_freeze(current_big_file_ptt);
                }       
        }

	return 0;
}

int app_switch_start_filter_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
                print_asap("app switch start filter is set to %d", app_switch_start_filter);
        }

	return 0;
}


int switch_target_pid_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
                int uid, idx;
                switch_target_task = find_task_by_vpid(switch_target_pid);
                if (!switch_target_task) {
                       print_asap("Invalid PID to switch_target_pid\n");
                       return 1;
                }
                uid = switch_target_task->cred->uid.val;
                for (idx = 0; idx < MAX_APP_NUM; idx++) {
                        if (!app_name_table[idx]) {
                                print_asap("ERROR: NO MATCHED APP ON REGISTER TABLE");
                                return 1;
                        }
                        if (uid == app_uid_table[idx])
                                break;
                }
                switch_target_idx = idx;  
                current_file_ptt = app_file_ptt_table[idx];
                current_big_file_ptt = app_big_file_ptt_table[idx];
                current_file_ct = app_all_file_ptt_table[idx];
                
                current_anon_table = app_anon_table[idx];
                current_anon_ptt = current_anon_table->ptt;

                if(app_pid_table[idx] != switch_target_pid){
                    anon_ptt_clear(current_anon_ptt);
                    anon_ptt_clear(current_anon_table->ct);
                    file_ptt_clear(current_file_ptt);
                    file_ptt_clear(current_big_file_ptt);
                }
                app_pid_table[idx] = switch_target_pid;

                print_asap("Target Process Set: %lu %s", switch_target_task->pid, switch_target_task->comm);
        }

	return 0;
}

int perf_test_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	return 0;
}

int cur_ppthreads_num_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) { 
                print_asap("cur_swapperfd_num updated %d\n", cur_ppthreads_num);
        }

	return 0;
}

int hot_evict_num_sysctl_handler(struct ctl_table *table, int write, 
                void __user *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) { 
                print_asap("hot_evict_num updated %d\n", hot_evict_num);
        }

	return 0;
}

int swap_in_cnt_sysctl_handler(struct ctl_table *table, int write, 
                void __user *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) { 
                print_asap("swap_in_cnt updated %d\n", swap_in_called_cnt.counter);
        }

	return 0;
}

int debug_file_fetch_sysctl_handler(struct ctl_table *table, int write, 
                void __user *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) { 
                print_asap("debug_file_fetch updated %d\n", debug_file_fetch);
        }

	return 0;
}

int trace_filter_sysctl_handler(struct ctl_table *table, int write, 
                void __user *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) { 
                print_asap("trace_filter updated %d\n", trace_filter);
        }

	return 0;
}

int file_prepaging_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
        }

	return 0;
}

int anon_prepaging_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
        }

	return 0;
}


int anon_page_dump;
int anon_page_dump_clear_af;

static void _anon_page_dump(pid_t pid) {
        struct task_struct *task = find_task_by_vpid(pid);
        unsigned long vpage;
        int accessed, idx;
        struct vm_area_struct *vma;
        if (!task) {
                print_asap("task %d not found", pid); 
                return;
        }
        if (task->mm && task->mm->mmap) {
                for (vma = task->mm->mmap; vma; vma = vma->vm_next) {
                        for (vpage = vma->vm_start, idx = 0; vpage < vma->vm_end; vpage += PAGE_SIZE, idx++) {
                                pgd_t *pgd;
                                pud_t *pud;
                                pmd_t *pmd;
                                pte_t *pte;
                                pte_t entry;
                                struct mm_struct *mm = task->mm;
                        
                                // page table walk
                                pgd = pgd_offset(mm, vpage);
                                if (pgd_none(*pgd)) continue;

                                pud = pud_offset(pgd, vpage);
                                if (pud_none(*pud)) continue;
                        
                                pmd = pmd_offset(pud, vpage);
                                if (pmd_none(*pmd)) continue;
            
                                pte = pte_offset_kernel(pmd, vpage);
                                if (!pte || pte_none(*pte)) continue;
                                
                                if (pte_present(*pte)) {
                                        accessed = pte_young(*pte);
                                        if (anon_page_dump_clear_af) {
                                                entry = pte_mkold(*pte); 
                                        set_pte_at(mm, vpage, pte, entry);
                                        }
                                }
                                else
                                        accessed = 2; //swapped!
                                if(vma->vm_file){
                                        if(vma->vm_file->f_inode){
                                        trace_printk("FILE_PAGE_DUMP %s %lu %d %d\n",task->comm, vma->vm_file->f_inode->i_ino, idx, accessed);
                                        }
                                }else{
                                        trace_printk("ANON_PAGE_DUMP %s %lu %d %d\n",task->comm, vma->vm_start, idx, accessed);
                                }
                        }
                }
        }
}


int anon_page_dump_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos) {

        int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
                print_asap("anon_page_dump start for %d", anon_page_dump);
                _anon_page_dump(anon_page_dump);
                print_asap("anon_page_dump end for %d", anon_page_dump);
        }

	return 0;
}

static void _anon_page_swap(pid_t pid) {
        struct task_struct *task = find_task_by_vpid(pid);
        unsigned long vpage;
        int idx;
        struct vm_area_struct *vma;
        int cnt=0, ret=0;
        if (!task) {
                print_asap("task %d not found", pid); 
                return;
        }
        if (task->mm && task->mm->mmap) {
                for (vma = task->mm->mmap; vma; vma = vma->vm_next) {
                        if (vma->vm_file)
                                continue;
                        for (vpage = vma->vm_start, idx = 0; vpage < vma->vm_end; vpage += PAGE_SIZE, idx++) {
                                pgd_t *pgd;
                                pud_t *pud;
                                pmd_t *pmd;
                                pte_t *pte;
                                struct mm_struct *mm = task->mm;
                        
                                // page table walk
                                pgd = pgd_offset(mm, vpage);
                                if (pgd_none(*pgd)) continue;

                                pud = pud_offset(pgd, vpage);
                                if (pud_none(*pud)) continue;
                        
                                pmd = pmd_offset(pud, vpage);
                                if (pmd_none(*pmd)) continue;
            
                                pte = pte_offset_kernel(pmd, vpage);
                                if (!pte || pte_none(*pte)) continue;
                                
                                if (pte_present(*pte)) {
                                        continue;
                                }
                                else {
                                        unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_USER | FAULT_FLAG_REMOTE; 
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

                                        ret = handle_mm_fault(vma, vpage, flags); 
                                        
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

                                        cnt+=1;
                                }
                        }
                }
        }
        print_asap("%d pages swapped-in", cnt);
}

int anon_page_swap;
int anon_page_swap_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos) {

        int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
                print_asap("anon_page_swap start for %d", anon_page_swap);
                _anon_page_swap(anon_page_swap);
                print_asap("anon_page_swap end for %d", anon_page_swap);
        }

	return 0;
}


int do_nothing_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos) {

        int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
        }

	return 0;
}

void _launch_profile_start(void) {
        int idx, cursor;
        struct apg_hentry *hentry; 
        for (idx = 0; idx < MAX_APP_NUM; idx++) {
                if (!app_name_table[idx]) {
                        print_asap("ERROR: NO MATCHED APP ON REGISTER TABLE");
                        return;
                }
                if (strcmp(app_name_table[idx], launch_profile_start_target) == 0)
                        break;
        }
       
        // first profile
        if (!app_file_ptt_table[idx]) {
                app_file_ptt_table[idx] = (struct ptt *)vmalloc(sizeof(struct ptt));
                app_big_file_ptt_table[idx] = (struct ptt *)vmalloc(sizeof(struct ptt));
                app_all_file_ptt_table[idx] = (struct ptt *)vmalloc(sizeof(struct ptt));
                app_file_shadow_table[idx] = (struct shadow*)vmalloc(sizeof(struct shadow));
                ptt_init(app_file_ptt_table[idx], 1, 0);
                ptt_init(app_big_file_ptt_table[idx], 1, 0);
                ptt_init(app_all_file_ptt_table[idx], 1, 0);
                file_shadow_init(app_file_shadow_table[idx], 0);
                app_anon_table[idx] = (struct anon_table *)vmalloc(sizeof(struct anon_table));
                anon_table_init(app_anon_table[idx]);

        }

        // global ptt setup
        current_file_ptt = app_file_ptt_table[idx]; 
        current_big_file_ptt = app_big_file_ptt_table[idx];
        current_file_ct = app_all_file_ptt_table[idx];

        // profile start
        hash_for_each(app_apg_table[idx]->htable, cursor, hentry, node)
                _file_page_dump(hentry->tgid, 1, 0);

        print_asap("app file ptt profile start");

        switch_target_idx = idx;
        on_launch_profile = 1;
}


void _launch_profile_end(void) {
        int cursor;
        struct apg_hentry *hentry; 

        on_launch_profile = 0;

        print_asap("app file ptt profile end");
        hash_for_each(app_apg_table[switch_target_idx]->htable, cursor, hentry, node)
                _file_page_dump(hentry->tgid, 0, 1);

        print_asap("app file ptt profile check AB done");

}

void _file_ptt_gen(void) {
        int idx, cursor;
        struct file_shadow_hentry *hentry; 
        
        for (idx = 0; idx < MAX_APP_NUM; idx++) {
                if (!app_name_table[idx]) {
                        print_asap("ERROR: NO MATCHED APP ON REGISTER TABLE");
                        return;
                }
                if (strcmp(app_name_table[idx], file_ptt_gen_target) == 0)
                        break;
        }

        print_asap("file_ptt_gen start");
        // gen 1. add intersection of profiling to ptt one by one
        ptt_unfreeze(app_all_file_ptt_table[idx]);
        hash_for_each(app_file_shadow_table[idx]->htable, cursor, hentry, node) {
                if ( hentry->cnt >= file_ptt_gen_threshold ) {
                        file_ptt_add_one(app_all_file_ptt_table[idx], hentry->mapping, hentry->index, 1); 
                }
        }

        // gen 2. compact ptt !! 
        file_ptt_compact(app_all_file_ptt_table[idx], 1);
        
        ptt_freeze(app_all_file_ptt_table[idx]);

        
        print_asap("all_file_ptt overhead %s", app_name_table[idx]);
        file_ptt_report_stat(app_all_file_ptt_table[idx]);
}

void _apg_profile_start(void) {
        int idx;
        
        for (idx = 0; idx < MAX_APP_NUM; idx++) {
                if (!app_name_table[idx]) {
                        print_asap("ERROR: NO MATCHED APP ON REGISTER TABLE");
                        return;
                }
                if (strcmp(app_name_table[idx], apg_profile_start_target) == 0)
                        break;
        }
        
        if (!app_apg_table[idx]) {
                app_apg_table[idx] = (struct apg*)vmalloc(sizeof(struct apg));
                apg_init(app_apg_table[idx]);
        }
        // profile start
        switch_target_idx = idx;
        apg_profile_filter = 1;  
}

int apg_profile_end_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos) {

        int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
                int cursor;
                struct apg_hentry *hentry;
                struct hlist_node *tmp;
                struct task_struct *task;
                apg_profile_filter = 0;
                
                hash_for_each_safe(app_apg_table[switch_target_idx]->htable, cursor, tmp, hentry, node) {
                        task = find_task_by_vpid(hentry->tgid);
                        if (!task) 
                                apg_del(app_apg_table[switch_target_idx], hentry->tgid);
                        else
                                print_asap("%s apg: %s %d", app_name_table[switch_target_idx], task->comm, task->tgid);
                }
        }

	return 0;
}

int apg_gen_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos) {

        int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
                int cursor;
                struct apg_hentry *hentry;
                struct hlist_node *tmp;
                struct task_struct *task;
                hash_for_each_safe(app_apg_table[switch_target_idx]->htable, cursor, tmp, hentry, node) {
                        task = find_task_by_vpid(hentry->tgid);
                        if (!task || hentry->cnt < file_ptt_gen_threshold) 
                                apg_del(app_apg_table[switch_target_idx], hentry->tgid);
                        else
                                print_asap("%s apg final: %s %d", app_name_table[switch_target_idx], task->comm, task->tgid);
                }
        }

	return 0;
}
int clear_anonlist_sysctl_handler(struct ctl_table *table, int write, 
                void __user *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
                if(current_anon_ptt)
                        anon_ptt_clear(current_anon_ptt);
                if(current_anon_table)
                        anon_ptt_clear(current_anon_table->ct);
        }

	return 0;
}

unsigned int default_tick;
int default_tick_sysctl_handler(struct ctl_table *table, int write,
                void __user *buffer, size_t *length, loff_t *ppos) 
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
                if(current_anon_table){
                        print_asap("changed default_tick\n");
                        current_anon_table->start_tick = default_tick;
                }
                print_asap("set global default_tick\n");
        }

	return 0;
}


static bool run_on_little(int kid) {
        if (kid >= ASAP_CORE_NUM + ASAP_LITTLE_CORE_NUM || (kid >= ASAP_LITTLE_CORE_NUM && kid < ASAP_CORE_NUM))
                return 1;
        return 0;
}

int open_one_core_sysctl_handler(struct ctl_table *table, int write,
                void __user *buffer, size_t *length, loff_t *ppos) 
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
                int kid;
                if (open_one_core == 0) {
                        for(kid = 0; kid < ASAP_CORE_NUM; kid++) {
                                if (ppthreads[kid])
                                        continue;

                                if (kid >= ASAP_CORE_NUM) {
                                        struct sched_param param = { .sched_priority = 0 };
                                        if (run_on_little(kid)) 
                                                sched_setscheduler(ppthreads[kid], SCHED_IDLE, &param);
                                                //set_user_nice(ppthreads[kid], MAX_NICE);
                                } else {
                                        struct sched_param param = { .sched_priority = 0 };
                                        sched_setscheduler(ppthreads[kid], SCHED_IDLE, &param);
                                }
                        }
                }

                if (open_one_core == 1 || open_one_core == 2) {
                        for(kid = 0; kid < ASAP_CORE_NUM; kid++) {
                                if (ppthreads[kid])
                                        continue;

                                if (kid >= ASAP_CORE_NUM) {
                                        struct sched_param param = { .sched_priority = 0 };
                                        sched_setscheduler(ppthreads[kid], SCHED_NORMAL, &param);
                                                //set_user_nice(ppthreads[kid], MAX_NICE);
                                } else {
                                        struct sched_param param = { .sched_priority = 0 };
                                        sched_setscheduler(ppthreads[kid], SCHED_NORMAL, &param);
                                }
                        }
                } 
        }

	return 0;
}




int file_ptt_print;
int file_ptt_dump_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos) {

        int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
                print_asap("start current_file_ptt dump");
                file_ptt_dump(current_file_ptt);
                print_asap("start current_big_file_ptt dump");
                file_ptt_dump(current_big_file_ptt);  
        }

	return 0;
}




static int __init app_table_init(void)
{
        int idx;
        for (idx = 0; idx < MAX_APP_NUM; idx++) {
                app_name_table[idx] = NULL;
                app_uid_table[idx] = 0;
                app_big_file_ptt_table[idx] = NULL;
                app_file_ptt_table[idx] = NULL;
                app_file_shadow_table[idx] = NULL; 
                app_apg_table[idx] = NULL;
        }
        /* generated code */
        app_name_table[0] = "com.rovio.angrybirds";
        app_name_table[1] = "com.quora.android";
        app_name_table[2] = "com.facebook.orca";
        app_name_table[3] = "com.facebook.katana";
        app_name_table[4] = "com.twitter.android";
        app_name_table[5] = "com.google.android.youtube";
        app_name_table[6] = "com.nytimes.android";
        app_name_table[7] = "com.android.chrome";
        app_name_table[8] = "com.king.candycrushsaga";
        app_uid_table[0] = 10134;
        app_uid_table[1] = 10133;
        app_uid_table[2] = 10156;
        app_uid_table[3] = 10123;
        app_uid_table[4] = 10142;
        app_uid_table[5] = 10141;
        app_uid_table[6] = 10131;
        app_uid_table[7] = 10120;
        app_uid_table[8] = 10126;
                
                
        
        return 0;
}

module_init(app_table_init)

#endif
