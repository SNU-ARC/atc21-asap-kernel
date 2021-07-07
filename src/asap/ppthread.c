/* SNU ARC Lab. ASAP */
/* ppthreads.c
 * prepaging threads implementation and initialization.
 * Life cycle of ppthredas is managed in sysctl.c
 * */

#include <asap/interface.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/irqflags.h>
#include <linux/kthread.h>
#include <linux/sched.h>

#include <uapi/linux/sched/types.h>
#ifdef ENABLE_ASAP
int kid_arr[PPTHREAD_NUM];
atomic_t kid_work[PPTHREAD_NUM];
pid_t ppthread_min_pid, ppthread_max_pid;
DECLARE_WAIT_QUEUE_HEAD(anon_ppthreads_wq);
DECLARE_WAIT_QUEUE_HEAD(node_ppthreads_wq);
struct wait_queue_head file_ppthreads_wqs[ASAP_CORE_NUM];

struct task_struct *ppthreads[PPTHREAD_NUM];
struct task_struct *node_ppthreads[PPTHREAD_NUM];
struct task_struct *switch_target_task;
int switch_target_idx;
int ppthreads_stat[PPTHREAD_NUM];
int open_one_core;
int iorap_core;

static bool run_on_little(int kid) {
        if (kid >= ASAP_CORE_NUM + ASAP_LITTLE_CORE_NUM || (kid >= ASAP_LITTLE_CORE_NUM && kid < ASAP_CORE_NUM))
                return 1;
        return 0;
}

static int node_ppthread(void* data) {
        int kid = *((int *)data);
        struct ptt *ptt;
        struct wait_queue_head *wq = &node_ppthreads_wq;
        
        for ( ; ; ) {
                // sleep
                print_asap("go to sleep\n", kid); 
                wait_event_interruptible(*wq, atomic_read(&kid_work[kid]));  
                if (atomic_read(&kid_work[kid])) {  
                        ptt = current_file_ptt;
                        if (!run_on_little(kid) && (ptt == current_big_file_ptt)) {
                                ptt = current_big_file_ptt;
                                print_asap("I'm gonna read big file");
                        }
                        
                        for( ; ; ) { 
                                int cnt;
                                // touch parts of each inode
                                cnt = file_ptt_fetch_one_unit(ptt, kid, 1);
                                if (cnt < 0) 
                                        break;
                        } 
                        
                        
                        atomic_set(&kid_work[kid], 0);
                }
        }
        return 0;
}



static int ppthread(void* data) {
        int kid = *((int *)data);
        struct ptt *ptt;
        struct wait_queue_head *wq = kid >= ASAP_CORE_NUM ? &file_ppthreads_wqs[smp_processor_id()] : &anon_ppthreads_wq;
  
        for ( ; ; ) {
                // sleep
                print_asap("go to sleep\n", kid); 
                wait_event_interruptible(*wq, atomic_read(&kid_work[kid]));  
                print_asap("wake up from sleep kid_work %d, running on cpu %d\n", kid, smp_processor_id()); 
 
                if (atomic_read(&kid_work[kid])) { 
                        /** ptt setup **/
                        ptt = kid >= ASAP_CORE_NUM ? current_file_ptt : current_anon_ptt;
                        
                        
                        if (iorap_mode && (smp_processor_id() == iorap_core)) {
                                ptt = current_big_file_ptt;
                        }
                       
                        // very default
                        if (!run_on_little(kid) && (ptt == current_file_ptt)) {
                                ptt = current_big_file_ptt;
                                print_asap("Selected as a big file thread");
                        } else if (core_scheduling_policy == 2 && (ptt == current_file_ptt)) {
                                ptt = current_big_file_ptt;
                                print_asap("Selected as a big file thread");
                        }
                        for( ; ; ) { 
                                int cnt;
                                cnt = ptt_fetch_one_unit(ptt, kid);
                                if (cnt < 0 && ptt == current_big_file_ptt) { // fallback condition 
                                        ptt = current_file_ptt;
                                        continue;
                                }
                                else if (cnt < 0) 
                                        break;
                                ppthreads_stat[kid] += cnt;
                        } 
                        print_asap("fetch %d pages", ppthreads_stat[kid]);
                        atomic_set(&kid_work[kid], 0);
                }
        }
        return 0;
}

int ppthreads_run(void)
{
	int ret = 0;
        int kid;

        for(kid = 0; kid < PPTHREAD_NUM; kid++) {
                if (ppthreads[kid])
		        continue;
                kid_arr[kid] = kid;
                atomic_set(&kid_work[kid], 0);
                
                // binds kthread to cpu kid
                if (kid >= ASAP_CORE_NUM) { // file ppthreads
	                struct sched_param param = { .sched_priority = 0 };
                        ppthreads[kid] = kthread_create_on_cpu(ppthread,
					  &kid_arr[kid],
					  (ASAP_CORE_NUM - 1- (kid%ASAP_CORE_NUM)),
					  "filepp%u");
                                
                        if ( (ASAP_CORE_NUM - 1- (kid%ASAP_CORE_NUM)) == 5 ) {
                                sched_setscheduler(ppthreads[kid], SCHED_NORMAL, &param);
                        } else {
                                sched_setscheduler(ppthreads[kid], SCHED_IDLE, &param);
                        }                
                } else { // anon ppthreads and node ppthreads
                        struct sched_param param = { .sched_priority = 0 };
                        ppthreads[kid] = kthread_create_on_cpu(ppthread,
					  &kid_arr[kid],
					  ASAP_CORE_NUM - 1- (kid%ASAP_CORE_NUM),
					  "anonpp%u");
                        node_ppthreads[kid] = kthread_create_on_cpu(node_ppthread,
					  &kid_arr[kid],
					  ASAP_CORE_NUM - 1 - (kid%ASAP_CORE_NUM),
					  "nodepp%u");

                        sched_setscheduler(ppthreads[kid], SCHED_IDLE, &param);
                }

                if (!IS_ERR(ppthreads[kid])) {				   
		        wake_up_process(ppthreads[kid]);
		        if (node_ppthreads[kid])
                                wake_up_process(node_ppthreads[kid]);
                }
                
                
                if (ppthread_min_pid > ppthreads[kid]->pid)
                        ppthread_min_pid = ppthreads[kid]->pid;               
                if (ppthread_max_pid < ppthreads[kid]->pid)
                        ppthread_max_pid = ppthreads[kid]->pid;
        }
	return ret;
}


static int __init ppthreads_init(void)
{
        int idx;
        ppthread_min_pid = 9999999;
        ppthread_max_pid = 0;
        
        for (idx = 0; idx < ASAP_CORE_NUM; idx++) {
                init_waitqueue_head(&file_ppthreads_wqs[idx]);
        } 
        
        cur_ppthreads_num = PPTHREAD_NUM;
        ppthreads_run();
	return 0;
}

module_init(ppthreads_init)
#endif /* ENABLE_ASAP */
