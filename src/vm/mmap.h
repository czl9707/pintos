#ifndef VM_MMAP_H
#define VM_MMAP_H

#include "filesys/file.h"
#include "hash.h"

#define MMAP_ERROR -1

typedef int mapid_t;

struct mmap_file {
    struct hash_elem elem;
    mapid_t mapid;
    struct process* process;
    struct file* file;
    void* vir_addr;
};

void mmap_init(void);
mapid_t mmap_map_file (struct file*, void*);
void mmap_unmap_file (mapid_t);
void mmap_table_clean_up(void);

unsigned mmap_hash_hash_func(const struct hash_elem *elem, UNUSED void* aux);
bool mmap_hash_less_func(const struct hash_elem *h1, const struct hash_elem *h2, UNUSED void* aux);
void mmap_hash_free_func(struct hash_elem *elem, UNUSED void* aux);

#endif 