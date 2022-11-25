#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "filesys/directory.h"

typedef int fd_t;

struct opened_file {
    fd_t fd;                                /**< File Descriptor */
    struct list_elem elem;                  /**< List element */
    struct file *f;                         /**< File struct handler */
};

void syscall_init (void);

#endif /**< userprog/syscall.h */
