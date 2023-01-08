#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <console.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "userprog/userfile.h"
#include "vm/mmap.h"

static void syscall_handler(struct intr_frame *);
static void parse_args(struct intr_frame *, int, void *(*)[], void*);
static void mem_is_valid(const void*, size_t, void*);
static void addr_is_valid(const void*, void*);

static void halt (void);
static void exit (int);
static pid_t exec (void*, const char *);
static int wait (void*, pid_t);
static bool create (void*, const char *, unsigned);
static bool remove (void*, const char *);
static fd_t open (void*, const char *);
static int filesize (void*, fd_t);
static int read (void*, fd_t , void *, unsigned);
static int write (void*, fd_t, const void *, unsigned);
static void seek (void*, fd_t , unsigned);
static unsigned tell (void*, fd_t);
static void close (void*, fd_t);
static mapid_t mmap (void*, fd_t fd, void *addr);
static void munmap (void*, mapid_t mapid);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
  mem_is_valid(f->esp, 4, f->esp);

  enum syscall_num syscall_num = *(enum syscall_num *)(f->esp);
  void *args[3];

  switch (syscall_num)
  {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    parse_args(f, 1, &args, f->esp);
    exit(*(int*)args[0]);
    break;
  case SYS_EXEC:
    parse_args(f, 1, &args, f->esp);
    f->eax = exec(f->esp, *(const char**)args[0]);
    break;
  case SYS_WAIT:
    parse_args(f, 1, &args, f->esp);
    f->eax = wait(f->esp, *(pid_t*)args[0]);
    break;
  case SYS_CREATE:
    parse_args(f, 2, &args, f->esp);
    f->eax = create(f->esp, *(const char**)args[0], *(unsigned*)args[1]);
    break;
  case SYS_REMOVE:
    parse_args(f, 1, &args, f->esp);
    f->eax = remove(f->esp, *(const char**)args[0]);
    break;
  case SYS_OPEN:
    parse_args(f, 1, &args, f->esp);
    f->eax = open(f->esp, *(char**)args[0]);
    break;
  case SYS_FILESIZE:
    parse_args(f, 1, &args, f->esp);
    f->eax = filesize(f->esp, *(fd_t*)args[0]);    
    break;
  case SYS_READ:
    parse_args(f, 3, &args, f->esp);
    f->eax = read(f->esp, *(fd_t*)args[0], *(void**)args[1], *(unsigned*)args[2]);
    break;
  case SYS_WRITE:
    parse_args(f, 3, &args, f->esp);
    f->eax = write(f->esp, *(fd_t*)args[0], *(void**)args[1], *(unsigned*)args[2]);
    break;
  case SYS_SEEK:
    parse_args(f, 2, &args, f->esp);
    seek(f->esp, *(fd_t*)args[0], *(unsigned*)args[1]);
    break;
  case SYS_TELL:
    parse_args(f, 1, &args, f->esp);
    f->eax = tell(f->esp, *(fd_t*)args[0]);
    break;
  case SYS_CLOSE:
    parse_args(f, 1, &args, f->esp);
    close(f->esp, *(fd_t*)args[0]);
    break;
  case SYS_MMAP:
    parse_args(f, 2, &args, f->esp);
    f->eax = mmap(f->esp, *(fd_t*)args[0], *(void**)args[1]);
    break;
  case SYS_MUNMAP:
    parse_args(f, 1, &args, f->esp);
    munmap(f->esp, *(mapid_t*)args[0]);
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

static void parse_args(struct intr_frame *f, int arg_nums, void *(*args)[], void* esp)
{
  mem_is_valid(f->esp + 4, 4 * arg_nums, esp);
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
static pid_t exec (void* esp, const char *cmd_line){
  mem_is_valid(cmd_line, 4, esp);
  pid_t pid = process_execute(cmd_line);
  return pid;
}

/* Waits for a child process pid and retrieves the child's exit status. */
static int wait (UNUSED void* esp, pid_t pid){
  return process_wait(pid);
}

/* Creates a new file called file initially initial_size bytes 
  in size. Returns true if successful, false otherwise. */
static bool create (void* esp, const char *file, unsigned initial_size){
  addr_is_valid(file, esp);
  if (file == NULL) exit(-1);
  return userfile_create(file, initial_size);
}

static bool remove (void* esp, const char *file){
  addr_is_valid(file, esp);
  if (file == NULL) exit(-1);
  return userfile_remove(file);
}

/* Opens the file called file. 
  Returns a nonnegative integer handle 
  called a "file descriptor" (fd), 
  or -1 if the file could not be opened. */
static fd_t open (void* esp, const char *file){
  addr_is_valid(file, esp);
  if (file == NULL) exit(-1);
  return userfile_open(file);
}

/* Returns the size, in bytes, of the file open as fd. */
static int filesize (UNUSED void* esp, fd_t fd){
  return userfile_filesize(fd);
}

/* Reads size bytes from the file open as fd into buffer. 
  Returns the number of bytes actually read (0 at end of file), 
  or -1 if the file could not be read 
  (due to a condition other than end of file).  */
static int read (void* esp, fd_t fd, void *buffer, unsigned size){
  mem_is_valid(buffer, size, esp);
  if (!page_is_writable(process_current(), buffer))
    exit(-1);

  if (fd == 0){
    unsigned read_size = 0;
    char c;
    
    for (c = input_getc(); c != '\r' && read_size < size; c = input_getc()){
      *(char*)(buffer + read_size) = c;
      read_size ++;
    }

    return read_size;
  }

  return userfile_read(fd, buffer, size);
}

/* Writes size bytes from buffer to the open file fd. 
  Returns the number of bytes actually written, 
  which may be less than size if some bytes could not be written. */
static int write (void* esp, fd_t fd, const void *buffer, unsigned size){
  mem_is_valid(buffer, size, esp);
  if (fd == 1){
    putbuf(buffer, size);
  }

  return userfile_write(fd, buffer, size);
}

static void seek (UNUSED void* esp, fd_t fd, unsigned position){
  userfile_seek(fd, position);
}

static unsigned tell (UNUSED void* esp, fd_t fd){
  return userfile_tell(fd);
}

static void close (UNUSED void* esp, fd_t fd){
  userfile_close(fd);
}

static mapid_t mmap (UNUSED void* esp, fd_t fd, void *addr){
  if (addr == NULL) return MMAP_ERROR;
  if (pg_ofs(addr) != 0) return MMAP_ERROR;
  if (fd == 0 || fd == 1) return MMAP_ERROR;

  struct file* f = get_file_by_fd(fd); 
  if (f == NULL) return MMAP_ERROR;
  return mmap_map_file(f, addr);
}

static void munmap (UNUSED void* esp, mapid_t mapid){
  mmap_unmap_file(mapid);
}

// *************************** Static helper function ***************************

static void mem_is_valid(const void* addr, size_t size, void* esp){
  size_t s = 0;

  for (;s < size; s += PGSIZE){
    addr_is_valid(addr + s, esp);
  }
  addr_is_valid(addr + size - 1, esp);
}

static void addr_is_valid(const void* addr, void* esp){
  if (!is_user_vaddr(addr)) goto exit;
  if (pagedir_get_page(pagedir_current(), addr) != NULL || 
    load_page(process_current(), (void*)addr)) return;
  if (addr >= esp &&
    load_stack(process_current(), esp, (void*)addr)) return;

  exit:
  exit(-1);
  NOT_REACHED();
}