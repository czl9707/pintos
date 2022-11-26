#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <console.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

static struct list opened_files;
static struct lock file_list_access_lock;

static void syscall_handler(struct intr_frame *);
static void parse_args(struct intr_frame *, int, void *(*)[]);
static void mem_is_valid(const void*, size_t);
static void addr_is_valid(const void*);
static bool opened_file_elem_comp(const struct list_elem *, const struct list_elem *, UNUSED void *);
static fd_t next_valid_fd(void);
static struct opened_file *get_opened_file_from_fd(fd_t);

static void halt (void);
static void exit (int);
static pid_t exec (const char *);
static int wait (pid_t);
static bool create (const char *, unsigned);
static bool remove (const char *);
static fd_t open (const char *);
static int filesize (fd_t);
static int read (fd_t , void *, unsigned);
static int write (fd_t, const void *, unsigned);
static void seek (fd_t , unsigned);
static unsigned tell (fd_t);
static void close (fd_t);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&opened_files);
  lock_init(&file_list_access_lock);
}

static void
syscall_handler(struct intr_frame *f)
{
  mem_is_valid(f->esp, 4);

  enum syscall_num syscall_num = *(enum syscall_num *)(f->esp);
  void *args[3];

  switch (syscall_num)
  {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    parse_args(f, 1, &args);
    exit(*(int*)args[0]);
    break;
  case SYS_EXEC:
    parse_args(f, 1, &args);
    f->eax = exec(*(const char**)args[0]);
    break;
  case SYS_WAIT:
    parse_args(f, 1, &args);
    f->eax = wait(*(pid_t*)args[0]);
    break;
  case SYS_CREATE:
    parse_args(f, 2, &args);
    f->eax = create(*(const char**)args[0], *(unsigned*)args[1]);
    break;
  case SYS_REMOVE:
    parse_args(f, 1, &args);
    f->eax = remove(*(const char**)args[0]);
    break;
  case SYS_OPEN:
    parse_args(f, 1, &args);
    f->eax = open(*(char**)args[0]);
    break;
  case SYS_FILESIZE:
    parse_args(f, 1, &args);
    f->eax = filesize(*(fd_t*)args[0]);    
    break;
  case SYS_READ:
    parse_args(f, 3, &args);
    f->eax = read(*(fd_t*)args[0], *(void**)args[1], *(unsigned*)args[2]);
    break;
  case SYS_WRITE:
    parse_args(f, 3, &args);
    f->eax = write(*(fd_t*)args[0], *(void**)args[1], *(unsigned*)args[2]);
    break;
  case SYS_SEEK:
    parse_args(f, 2, &args);
    seek(*(fd_t*)args[0], *(unsigned*)args[1]);
    break;
  case SYS_TELL:
    parse_args(f, 1, &args);
    f->eax = tell(*(fd_t*)args[0]);
    break;
  case SYS_CLOSE:
    parse_args(f, 1, &args);
    close(*(fd_t*)args[0]);
    break;
  case SYS_MMAP:
    break;
  case SYS_MUNMAP:
    break;
  case SYS_CHDIR:
    break;
  case SYS_MKDIR:
    break;
  case SYS_READDIR:
    break;
  case SYS_ISDIR:
    break;
  case SYS_INUMBER:
    break;
  default:
    break;
  }
}

static void parse_args(struct intr_frame *f, int arg_nums, void *(*args)[])
{
  mem_is_valid(f->esp + 4, 4 * arg_nums);
  for (int i = 0; i < arg_nums; i++)
  {
    (*args)[i] = f->esp + i * 4 + 4;
  }
}

// *************************** handlers ********************************

/* This should be seldom used, 
  because you lose some information about 
  possible deadlock situations, etc. */
static void halt(void)
{
  shutdown_power_off();
  NOT_REACHED();
}

/* Conventionally, a status of 0 indicates success 
  and nonzero values indicate errors. */
static void exit (int status){
  struct process *p = thread_current()->process;
  p->exit_status = status;
  thread_exit ();
  NOT_REACHED ();
}

/* Runs the executable whose name is given in cmd_line, 
  passing any given arguments, 
  and returns the new process's program id (pid). */
static pid_t exec (const char *cmd_line){
  mem_is_valid(cmd_line, 4);
  pid_t pid = process_execute(cmd_line);
  return pid;
}

/* Waits for a child process pid and retrieves the child's exit status. */
static int wait (pid_t pid){
  return process_wait(pid);
}

/* Creates a new file called file initially initial_size bytes 
  in size. Returns true if successful, false otherwise. */
static bool create (const char *file, unsigned initial_size){
  addr_is_valid(file);
  if (file == NULL) exit(-1);

  return filesys_create(file, initial_size);
}

static bool remove (const char *file){
  // printf("SYSCALL remove\n");
  addr_is_valid(file);
  return filesys_remove(file);
}

/* Opens the file called file. 
  Returns a nonnegative integer handle 
  called a "file descriptor" (fd), 
  or -1 if the file could not be opened. */
static fd_t open (const char *file){
  addr_is_valid(file);
  if (file == NULL) exit(-1);

  struct file *f = filesys_open(file);
  if (f == NULL) return -1;

  lock_acquire(&file_list_access_lock);
  
  fd_t fd = next_valid_fd();
  struct opened_file *of = malloc (sizeof (struct opened_file));
  of->f = f;
  of->fd = fd;
  of->p = process_current();
  list_insert_ordered(&opened_files, &of->elem, opened_file_elem_comp, NULL);
  lock_release(&file_list_access_lock);

  return of->fd;
}

/* Returns the size, in bytes, of the file open as fd. */
static int filesize (fd_t fd){
  struct opened_file *op = get_opened_file_from_fd(fd);
  if (op == NULL || op->f == NULL) return -1;

  return file_length(op->f);
}

/* Reads size bytes from the file open as fd into buffer. 
  Returns the number of bytes actually read (0 at end of file), 
  or -1 if the file could not be read 
  (due to a condition other than end of file).  */
static int read (fd_t fd, void *buffer, unsigned size){
  // printf("SYSCALL read %d\n", fd);
  mem_is_valid(buffer, size);
  if (fd == 0){
    unsigned read_size = 0;
    char c;
    
    for (c = input_getc(); c != '\r' && read_size < size; c = input_getc()){
      *(char*)(buffer + read_size) = c;
      read_size ++;
    }

    return read_size;
  }

  struct opened_file *op = get_opened_file_from_fd(fd);
  if (op == NULL || op->f == NULL) return -1;

  return file_read(op->f, buffer, size);
}

/* Writes size bytes from buffer to the open file fd. 
  Returns the number of bytes actually written, 
  which may be less than size if some bytes could not be written. */
static int write (fd_t fd, const void *buffer, unsigned size){
  // printf("SYSCALL write %d\n", fd);
  mem_is_valid(buffer, size);
  if (fd == 1){
    putbuf(buffer, size);
  }

  struct opened_file *op = get_opened_file_from_fd(fd);
  if (op == NULL || op->f == NULL) return -1;

  return file_write(op->f, buffer, size);
}

static void seek (fd_t fd, unsigned position){
  // printf("SYSCALL seek\n");
  struct opened_file *op = get_opened_file_from_fd(fd);
  if (op == NULL || op->f == NULL) return;

  op->f->pos = position;
}

static unsigned tell (fd_t fd){
  // printf("SYSCALL tell\n");
  struct opened_file *op = get_opened_file_from_fd(fd);
  if (op == NULL || op->f == NULL) return 0;
  return op->f->pos;
}

static void close (fd_t fd){
  // printf("SYSCALL close\n");
  struct opened_file *op = get_opened_file_from_fd(fd);
  if (op == NULL || op->f == NULL) return;
  if (process_current() != op->p) return;

  lock_acquire(&file_list_access_lock);
  list_remove(&op->elem);
  file_close(op->f);
  free(op);
  lock_release(&file_list_access_lock);
}

// *************************** Static helper function ***************************

static void mem_is_valid(const void* addr, size_t size){
  size_t s = 0;

  for (;s < size; s += PGSIZE){
    addr_is_valid(addr + s);
  }
  addr_is_valid(addr + size - 1);
}

static void addr_is_valid(const void* addr){
  if (is_user_vaddr(addr) && pagedir_get_page(pagedir_current(), addr) != NULL){
    return;
  }
  exit(-1);
  NOT_REACHED();
}

/** This function should always be called within an external interruption */
static fd_t next_valid_fd(void){
  fd_t fd = 2, fd_iter;
  struct list_elem *elem = list_begin(&opened_files);
  struct list_elem *end_elem = list_end(&opened_files);

  for (; elem != end_elem; elem = list_next(elem)){
    fd_iter = list_entry(elem, struct opened_file, elem)->fd;
    if (fd == fd_iter) fd ++;
    else return fd;
  }

  return fd;
}

static struct opened_file *get_opened_file_from_fd(fd_t fd){
  struct list_elem *elem = list_begin(&opened_files), *elem_end = list_end(&opened_files);
  struct opened_file *op;

  for (;elem != elem_end; elem = list_next(elem)){
    op = list_entry(elem, struct opened_file, elem);
    if (op->fd == fd) return op;
    else if (op->fd > fd) return NULL; 
  }

  return NULL;
}

static bool opened_file_elem_comp(const struct list_elem *l_a, const struct list_elem *l_b, UNUSED void *aux){
  struct opened_file *of_a = list_entry(l_a, struct opened_file, elem);
  struct opened_file *of_b = list_entry(l_b, struct opened_file, elem);
  return of_a->fd < of_b->fd;
}