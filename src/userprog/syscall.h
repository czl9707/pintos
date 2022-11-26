#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "filesys/directory.h"
#include "filesys/file.h"

typedef int fd_t;

struct opened_file {
    struct process *p;                      /**< Process opened this file */
    struct file *f;                         /**< File struct handler */
    fd_t fd;                                /**< File Descriptor */
    struct list_elem elem;                  /**< List element */
};

void syscall_init (void);

#endif /**< userprog/syscall.h */
