#ifndef USERPROG_USERFILE_H
#define USERPROG_USERFILE_H

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

void userfile_init(void);
void clean_opened_file_by_pid(pid_t);

bool userfile_create (const char *, unsigned);
bool userfile_remove (const char *);
fd_t userfile_open (const char *);
int userfile_filesize (fd_t);
int userfile_read (fd_t , void *, unsigned);
int userfile_write (fd_t, const void *, unsigned);
void userfile_seek (fd_t , unsigned);
unsigned userfile_tell (fd_t);
void userfile_close (fd_t);
struct file* get_file_by_fd(fd_t);

// These two function just for vm level use temporarily, 
// should be removed in future lab.
void acquire_file_op_lock(void);
void release_file_op_lock(void);

#endif /**< userprog/userfile.h */