#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "filesys/directory.h"
#include "filesys/file.h"
#include "userprog/process.h"

typedef int fd_t;

struct opened_file {
    pid_t pid;                              /**< Process opened this file */
    struct file *f;                         /**< File struct handler */
    fd_t fd;                                /**< File Descriptor */
    struct list_elem elem;                  /**< List element */
};

void syscall_init (void);
void clean_opened_file_by_pid(pid_t);

#endif /**< userprog/syscall.h */
