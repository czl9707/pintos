#include "userprog/userfile.h"
#include <stdio.h>
#include "filesys/filesys.h"

static struct list opened_files;
static struct lock opened_files_access;
// a lock for file operation probably should not be handled by usercall level,
// should be removed in future lab.
static struct lock file_op_lock;

static bool opened_file_elem_comp(const struct list_elem *, const struct list_elem *, UNUSED void *);
static fd_t next_valid_fd(void);
static struct opened_file *get_opened_file_from_fd(fd_t);

// These two function just for vm level use temporarily, 
// should be removed in future lab.
void acquire_file_op_lock(void) { 
  lock_acquire(&file_op_lock);
}
void release_file_op_lock(void) {
  lock_release(&file_op_lock);
}

void userfile_init(void){
    list_init(&opened_files);
    lock_init(&opened_files_access);
    lock_init(&file_op_lock);
}

struct file* get_file_by_fd(fd_t fd){
  struct opened_file* of = get_opened_file_from_fd(fd);
  if (of == NULL) return NULL;
  return of->f;
}

bool userfile_create (const char *file, unsigned initial_size){
    acquire_file_op_lock();
    bool result = filesys_create(file, initial_size);
    release_file_op_lock();
    return result;
}

bool userfile_remove (const char *file){
    acquire_file_op_lock();
    bool result = filesys_remove(file);
    release_file_op_lock();
    return result;
}

fd_t userfile_open (const char *file){
    acquire_file_op_lock();
    struct file *f = filesys_open(file);
    release_file_op_lock();
    if (f == NULL) return -1;

    fd_t fd = next_valid_fd();
    struct opened_file *of = malloc (sizeof (struct opened_file));
    of->f = f;
    of->fd = fd;
    of->pid = process_current()->pid;

    lock_acquire(&opened_files_access);
    list_insert_ordered(&opened_files, &of->elem, opened_file_elem_comp, NULL);
    lock_release(&opened_files_access);

    return of->fd;
}

int userfile_filesize (fd_t fd){
    struct opened_file *of = get_opened_file_from_fd(fd);
    if (of == NULL || of->f == NULL) return -1;
    acquire_file_op_lock();
    int result = file_length(of->f);
    release_file_op_lock();
    return result;
}

int userfile_read (fd_t fd, void *buffer, unsigned size){
    struct opened_file *of = get_opened_file_from_fd(fd);
    if (of == NULL || of->f == NULL) return -1;

    acquire_file_op_lock();
    int result = file_read(of->f, buffer, size);
    release_file_op_lock();
    return result;
}

int userfile_write (fd_t fd, const void *buffer, unsigned size){
    struct opened_file *of = get_opened_file_from_fd(fd);
    if (of == NULL || of->f == NULL) return -1;

    acquire_file_op_lock();
    int result = file_write(of->f, buffer, size);
    release_file_op_lock();
    return result;
}

void userfile_seek (fd_t fd, unsigned position){
    struct opened_file *of = get_opened_file_from_fd(fd);
    if (of == NULL || of->f == NULL) return;

    of->f->pos = position;
}

unsigned userfile_tell (fd_t fd){
    struct opened_file *of = get_opened_file_from_fd(fd);
    if (of == NULL || of->f == NULL) return 0;
    return of->f->pos;
}

void userfile_close (fd_t fd){
    struct opened_file *of = get_opened_file_from_fd(fd);
    if (of == NULL || of->f == NULL) return;
    if (process_current()->pid != of->pid) return;

    lock_acquire(&opened_files_access);
    list_remove(&of->elem);
    lock_release(&opened_files_access);

    acquire_file_op_lock();
    file_close(of->f);
    release_file_op_lock();

    free(of);
}

/** This function should always be called within an external interruption */
static fd_t next_valid_fd(void){
  fd_t fd = 2, fd_iter;

  lock_acquire(&opened_files_access);

  struct list_elem *elem = list_begin(&opened_files);
  struct list_elem *end_elem = list_end(&opened_files);
  for (; elem != end_elem; elem = list_next(elem)){
    fd_iter = list_entry(elem, struct opened_file, elem)->fd;
    if (fd == fd_iter) fd ++;
    else break;
  }
  
  lock_release(&opened_files_access);
  return fd;
}

static struct opened_file *get_opened_file_from_fd(fd_t fd){
  lock_acquire(&opened_files_access);
  struct list_elem *elem = list_begin(&opened_files), *elem_end = list_end(&opened_files);
  struct opened_file *of, *result = NULL;

  for (;elem != elem_end; elem = list_next(elem)){
    of = list_entry(elem, struct opened_file, elem);
    if (of->fd == fd) result = of;
    else if (of->fd > fd) break; 
  }
  lock_release(&opened_files_access);
  return result;
}

static bool opened_file_elem_comp(const struct list_elem *l_a, const struct list_elem *l_b, UNUSED void *aux){
  struct opened_file *of_a = list_entry(l_a, struct opened_file, elem);
  struct opened_file *of_b = list_entry(l_b, struct opened_file, elem);
  return of_a->fd < of_b->fd;
}

void clean_opened_file_by_pid(pid_t pid){
  lock_acquire(&opened_files_access);
  struct list_elem *curr = list_begin(&opened_files), 
                  *end = list_end(&opened_files), 
                  *next;
  struct opened_file *of;

  while (curr != end){
    next = list_next(curr);
    of = list_entry(curr, struct opened_file, elem);
    if (of->pid == pid){
      list_remove(curr);
      file_close(of->f);
      free(of);
    }
    curr = next;
  }

  lock_release(&opened_files_access);
}