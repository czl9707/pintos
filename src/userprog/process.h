#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "list.h"

typedef int pid_t;

struct process {
    pid_t pid;
    int exit_status;
    struct semaphore waiting;        /**< When process exit will call sema_up. When other process waiting on this process, call sema_down on this. */
    struct semaphore loading;        /**< Control the loading phase of this process. */
    bool self_destroy;               /**< Destroy itself when called process_exit on it. */
    bool finish;                     /**< This process is finished. */
    bool waited;                     /**< This process is waited by its parent thread */

    struct list_elem allelem;
    struct list_elem elem;           /**< Used for parents children list */
    struct thread *thread;           /**< The thread running inside. */
    struct process *parent;          /**< Parent process. */
    struct list children;            /**< Keep track of all children processes */
};

void process_init(struct thread *t);
struct process *process_create(struct thread *t);
pid_t process_execute (const char *file_name);
int process_wait (pid_t);
void process_exit (void);
void process_activate (void);
struct process *process_current(void);

#endif /**< userprog/process.h */
