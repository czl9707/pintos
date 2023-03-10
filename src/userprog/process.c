#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "userprog/userfile.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

static struct list all_processes;
static struct lock processes_access;
struct process initial_process;

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static bool process_arg_passing(char**, char**, void**);

static struct process *process_get_by_tid(tid_t tid);
static void process_clean_up(struct process *p);
static bool process_is_parent(struct process *p, struct process *c);

void process_init(void){
  list_init(&all_processes);
  lock_init(&processes_access);

  sema_init(&initial_process.waiting, 0);
  sema_init(&initial_process.loading, 0);
  list_init(&initial_process.children);  
  hash_init(&initial_process.page_table, pte_hash_hash_func, pte_hash_less_func, NULL);
  initial_process.pid = initial_process.thread->tid;
  initial_process.thread->process = &initial_process;

  list_push_back(&all_processes, &initial_process.allelem);
}

// should only pass initial_thread into this function.
void initial_process_attach(struct thread *initial_thread){
  memset(&initial_process, 0, sizeof(struct process));
  initial_process.thread = initial_thread;
}

/** Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy, *actual_file_name, *save_ptr;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL) return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  
  actual_file_name = palloc_get_page(0);
  if (actual_file_name == NULL){
    palloc_free_page (fn_copy); 

    return TID_ERROR;
  }
  strlcpy (actual_file_name, file_name, PGSIZE);
  actual_file_name = strtok_r(actual_file_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (actual_file_name, PRI_DEFAULT, start_process, fn_copy);
  
  enum intr_level old_level = intr_disable();
  struct process *p = process_get_by_tid(tid);
  if (p != NULL) sema_down(&p->loading);
  intr_set_level(old_level);

  palloc_free_page (actual_file_name);
  palloc_free_page (fn_copy); 

  if (p!= NULL && p->finish && !p->started) tid = TID_ERROR;
  return tid;
}

/** A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name, *save_ptr;
  file_name = file_name_;
  file_name = strtok_r(file_name, " ", &save_ptr);
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);
  if (success) success = process_arg_passing(&file_name, &save_ptr, &if_.esp);

  struct process *p = process_current();
  if (success) {
    p->started = true;
  } else if (! success) {
    p->exit_status = -1;
    p->finish = true;
  }

  /* Finish loading anyway*/
  sema_up(&p->loading);
  
  /* If load failed, quit. */
  if (!success) {
    thread_exit ();
  }
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/** Helper function to pass args into start process. */
static bool process_arg_passing(char** file_name, char** save_ptr, void** stack){
  uint32_t argc = 0;
  size_t len;
  void *argv[32];
  char *token;

  // Insert argv[] chars
  for (token = *file_name ; token != NULL; token = strtok_r (NULL, " ", save_ptr)){
    len = strlen(token) + 1;
    *stack -= len;
    strlcpy((char*)(*stack), token, len);
    argv[argc] = *stack;
    argc ++;
    if (argc > 25) return false;
  }
  argv[argc] = NULL;

  // word-align
  len = (size_t)(*stack) % 4;
  *stack -= len;
  memset(*stack, 0, len);

  // Insert argv[] ptr
  for (int i = argc; i >= 0; i --){
    *stack -= 4;
    *(void**)(*stack) = argv[i];
  }

  //argv & argc & return addr
  *(void**)(*stack - 4) = *stack;
  *(uint32_t*)(*stack - 8) = argc;
  *(void**)(*stack - 12) = NULL;
  *stack -= 12;

  return true;
}

/** Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct process *p_curr = process_current();
  int result = 0;

  enum intr_level old_level = intr_disable();
  struct process *p = process_get_by_tid(child_tid);
  if (p == NULL || ! process_is_parent(p_curr, p)) result = -1;

  if (result != -1){
    sema_down(&p->waiting);
    result = p->exit_status;
    process_clean_up(p);
  }

  intr_set_level(old_level);
  return result;
}

/** Free the current process's resources. */
void
process_exit (void)
{
  struct thread *t = thread_current ();
  struct process *p = t->process;
  uint32_t *pd = t->pagedir;
  printf("%s: exit(%d)\n", t->name, p->exit_status);
  
  enum intr_level old_level = intr_disable();
  sema_up(&p->waiting);
  if (p->waited) process_clean_up(p);
  intr_set_level(old_level);
  
  /* Destroy the current process's page directory and switch back
    to the kernel-only page directory. */
  if (pd != NULL) 
  {
    /* Correct ordering here is crucial.  We must set
        cur->pagedir to NULL before switching page directories,
        so that a timer interrupt can't switch back to the
        process page directory.  We must activate the base page
        directory before destroying the process's page
        directory, or our active page directory will be one
        that's been freed (and cleared). */

    page_table_destroy(p);
    t->pagedir = NULL;
    pagedir_activate (NULL);
    pagedir_destroy (pd);
  }
}

/** Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

static struct process *process_get_by_tid(tid_t tid){
  struct list_elem *elem;
  struct process *p;
  struct list_elem *end;

  lock_acquire(&processes_access);
  end = list_end(&all_processes);
  for (elem = list_begin(&all_processes); elem != end; elem = list_next(elem)){
    p = list_entry(elem, struct process, allelem);
    if (p->pid == tid) break;
  }

  lock_release(&processes_access);

  if (elem == end) return NULL;
  return p;
}

/** This function will only be called within thread_start*/
struct process *process_create(struct thread *t){
  struct process *p = malloc(sizeof(struct process));
  memset(p, 0, sizeof(struct process));
  sema_init(&p->waiting, 0);
  sema_init(&p->loading, 0);
  list_init(&p->children);
  hash_init(&p->page_table, pte_hash_hash_func, pte_hash_less_func, NULL);
  p->thread = t;

  lock_acquire(&processes_access);
  list_push_back(&all_processes, &p->allelem);
  lock_release(&processes_access);

  return p;
}

static void process_clean_up(struct process *p){
  const struct list_elem *end = list_end(&p->children);
  struct list_elem *curr = list_begin(&p->children);
  struct process *curr_p;
  while (curr != end){
    curr_p = list_entry(curr, struct process, elem);
    curr = list_next(curr);

    if (curr_p->finish || curr_p->exit_status == -1) 
      process_clean_up(curr_p);
  }

  if (p->executable != NULL) file_close(p->executable);
  list_remove(&p->allelem);
  list_remove(&p->elem);

  free(p);
}

static bool process_is_parent(struct process *p, struct process *c){
  return p == c->parent;
}

struct process *process_current(void){
  return thread_current()->process;
}


/** We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/** ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/** For use with ELF types in printf(). */
#define PE32Wx PRIx32   /**< Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /**< Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /**< Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /**< Print Elf32_Half in hexadecimal. */

/** Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/** Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/** Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /**< Ignore. */
#define PT_LOAD    1            /**< Loadable segment. */
#define PT_DYNAMIC 2            /**< Dynamic linking info. */
#define PT_INTERP  3            /**< Name of dynamic loader. */
#define PT_NOTE    4            /**< Auxiliary info. */
#define PT_SHLIB   5            /**< Reserved. */
#define PT_PHDR    6            /**< Program header table. */
#define PT_STACK   0x6474e551   /**< Stack segment. */

/** Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /**< Executable. */
#define PF_W 2          /**< Writable. */
#define PF_R 4          /**< Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/** Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  acquire_file_op_lock();
  file = filesys_open (file_name);
  release_file_op_lock();
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  
  process_current()->executable = file;
  if (file != NULL) file_deny_write(file);
  return success;
}


/** Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/** Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      pte_add(PAGE_FILE, process_current(), file, upage, 
              writable, ofs, page_read_bytes);

      /* Advance. */
      ofs += page_read_bytes;
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/** Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  *esp = PHYS_BASE;
  pte_add(PAGE_STACK, process_current(), NULL, *esp - PGSIZE, true, 0, PGSIZE);
  return load_page(process_current(), *esp - PGSIZE);
}