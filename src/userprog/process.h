#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "list.h"

typedef int pid_t;

struct process {
    int exit_status;
    struct semaphore waiting;        /**< When process exit will call sema_up. When other process waiting on this process, call sema_down on this. */
    struct semaphore loading;        /**< Control the loading phase of this process. */
    bool self_destroy;               /**< Destroy itself when called process_exit on it. */

    struct thread *child_thread;     /**< The thread running inside. */
    struct process *parent;          /**< Parent process. */
};

struct process *process_create(struct thread *t);
pid_t process_execute (const char *file_name);
int process_wait (pid_t);
void process_exit (void);
void process_activate (void);
struct process *process_current(void);

#endif /**< userprog/process.h */
