#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "list.h"
#include "hash.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "vm/mmap.h"

typedef int pid_t;

struct process {
    pid_t pid;
    int exit_status;
    bool started;                       /**< This process is successfully started */
    bool finish;                        /**< This process is finished. */
    bool waited;                        /**< This process has been waited. */
    struct file *executable;            /**< The executable this process using */
    struct thread *thread;              /**< The thread running inside. */
    struct process *parent;             /**< Parent process. */

    struct semaphore waiting;           /**< When process exit will call sema_up. When other process waiting on this process, call sema_down on this. */
    struct semaphore loading;           /**< Control the loading phase of this process. */
    struct list_elem allelem;           /**< Used for all process list */
    struct list_elem elem;              /**< Used for parents children list */
    struct list children;               /**< Keep track of all children processes */

    struct hash page_table;             /**< Store memory mapping */
};

void process_init(void);
void initial_process_attach(struct thread *t);
struct process *process_create(struct thread *t);
pid_t process_execute (const char *file_name);
int process_wait (pid_t);
void process_exit (void);
void process_activate (void);
struct process *process_current(void);

#endif /**< userprog/process.h */
