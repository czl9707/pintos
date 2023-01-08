#include "threads/vaddr.h"
#include <stdio.h>
#include "userprog/process.h"
#include "userprog/userfile.h"
#include "vm/mmap.h"
#include "vm/page.h"

static struct hash mmap_table;
static struct lock mmap_table_access;

static bool vaddr_is_valid(struct process*, void*, size_t);
static mapid_t insert_mmap_file(struct process*, struct file*, void*);
static void load_mmap_file(struct process*, struct file*, void*);
static mapid_t get_next_mapid(void);
static struct mmap_file* get_mmap_file_by_id(mapid_t); 
static void mmap_write_back(struct mmap_file*);

void mmap_init(void){
    lock_init(&mmap_table_access);
    // pass map itself as aux, allow handy unmap operation.
    hash_init(&mmap_table, mmap_hash_hash_func, mmap_hash_less_func, &mmap_table);
}

mapid_t mmap_map_file (struct file* file, void* vir_addr){
    acquire_file_op_lock();
    file = file_reopen(file);
    if (file == NULL){
        release_file_op_lock();
        return MMAP_ERROR;   
    }
    size_t size = file_length(file);
    release_file_op_lock();
    
    if (size == 0) return MMAP_ERROR;

    struct process* p = process_current();
    if (!vaddr_is_valid(p, vir_addr, size)) 
        return MMAP_ERROR;
    load_mmap_file(p, file, vir_addr);
    return insert_mmap_file(p, file, vir_addr);
}

void mmap_unmap_file (mapid_t mapid){
    lock_acquire(&mmap_table_access);
    struct mmap_file* mmapf = get_mmap_file_by_id(mapid);
    if (mmapf == NULL) {
        lock_release(&mmap_table_access);
        return;
    }

    mmap_write_back(mmapf);
    ASSERT(hash_delete(&mmap_table, &mmapf->elem) != NULL);
    free(mmapf);

    lock_release(&mmap_table_access);
}

mapid_t get_next_mapid(void){
    struct mmap_file mmapf;
    for (int i = 1; true; i++){
        mmapf.mapid = i;
        if (hash_find(&mmap_table, &mmapf.elem) == NULL) return i;
    }
}

void mmap_table_clean_up(void){
    hash_apply(&mmap_table, mmap_hash_free_func);
}

unsigned mmap_hash_hash_func(const struct hash_elem *elem, UNUSED void* aux){
    struct mmap_file* mmapf = hash_entry(elem, struct mmap_file, elem);
    return hash_int((int)mmapf->mapid);
}

bool mmap_hash_less_func(const struct hash_elem *h1, const struct hash_elem *h2, UNUSED void* aux){
    struct mmap_file* mmapf1 = hash_entry(h1, struct mmap_file, elem);
    struct mmap_file* mmapf2 = hash_entry(h2, struct mmap_file, elem);
    return mmapf1->mapid < mmapf2->mapid;
}

void mmap_hash_free_func(struct hash_elem *elem, UNUSED void* aux){
    struct mmap_file* mmapf = hash_entry(elem, struct mmap_file, elem);
    if (mmapf->process == process_current()){
        mmap_unmap_file(mmapf->mapid);
    }
}

static void mmap_write_back(struct mmap_file* mmapf){
    size_t size = file_length(mmapf->file);
    struct process* p = process_current();
    for (size_t step = 0; step < size; step += PGSIZE){
        page_remove(p, mmapf->vir_addr + step);
    }
}

static bool vaddr_is_valid(struct process* p, void* vir_addr, size_t size){
    size_t offset = 0;
    while (offset < size){
        if (find_pte_from_table(p, vir_addr + offset) != NULL) return false;
        offset += PGSIZE;
    }
    return true;
}

static mapid_t insert_mmap_file(struct process* p, struct file* f, void* vir_addr){
    struct mmap_file *mmapf = malloc(sizeof(struct mmap_file));
    mmapf->file = f;
    mmapf->vir_addr = vir_addr;
    mmapf->process = p;

    lock_acquire(&mmap_table_access);
    mmapf->mapid = get_next_mapid();
    ASSERT(hash_insert(&mmap_table, &mmapf->elem) == NULL);
    lock_release(&mmap_table_access);

    return mmapf->mapid;
}

static void load_mmap_file(struct process* p, struct file* f, void* vir_addr){
    int step, size = file_length(f);
    for (step = 0; step < size; step += PGSIZE){
        off_t read_bytes = size - step >= PGSIZE ? PGSIZE : size - step;
        pte_add(PAGE_MMAP, p, f, vir_addr + step, true, step, read_bytes);
    }
}

static struct mmap_file* get_mmap_file_by_id(mapid_t mapid){
    struct mmap_file mmapf;
    mmapf.mapid = mapid;
    struct hash_elem* elem = hash_find(&mmap_table, &mmapf.elem);
    if (elem == NULL) return NULL;
    return hash_entry(elem, struct mmap_file, elem);
}