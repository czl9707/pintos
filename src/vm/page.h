#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "hash.h"
#include "filesys/file.h"
#include "userprog/process.h"

enum page_type {
    PAGE_FILE,
    PAGE_STACK
};

struct page_table_entry{
    struct hash_elem elem;

    struct file* file;                  /**< File the pte opening, if not type is not PAGE_FILE, NULL. */
    struct frame* phy_frame;            /**< Pointer to the physical frame. phycial address || kernel page */
    struct process* process;            /**< Process holding this pte. */
    enum page_type type;                /**< Type of the pte. */
    void* vir_addr;                     /**< virtual address || user page */
    size_t page_read_bytes;
    off_t offset;
    bool writable;
    bool present;                       /**< P flag, indicate the page is using. */
};

void pte_add(enum page_type type, struct process* p, struct file* f, void* vir_addr,
            bool writable, off_t offset, size_t page_read_bytes);
void page_evict(struct process* p, void* vir_addr);
bool load_page(struct process* p, void* vir_addr);
bool load_stack(struct process* p, void* esp, void* vir_addr);
void page_table_destroy(struct process* p);
bool install_page(struct page_table_entry* pte, struct frame* phy_frame);

struct page_table_entry* find_pte_from_table(struct process* p, void* vir_addr);

unsigned pte_hash_hash_func(const struct hash_elem*, void*);
bool pte_hash_less_func(const struct hash_elem*, const struct hash_elem*, void*);
void pte_hash_free_func(struct hash_elem*, void*);

bool page_is_writable(struct process*, void*);

#endif /* vm/page.h */