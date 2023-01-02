#include "vm/page.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"

#define STACK_PG_LIMIT 128

static bool load_file(struct page_table_entry* pte, struct frame* phy_frame);

void pte_add(enum page_type type, struct process* process, struct file* file, void* vir_addr, bool writable,
            off_t offset, size_t page_read_bytes)
{
    struct page_table_entry* pte = malloc(sizeof(struct page_table_entry));
    pte->type = type;
    pte->process = process;
    pte->file = file;
    pte->vir_addr = vir_addr;
    pte->phy_frame = NULL;
    pte->writable = writable;
    pte->offset = offset;
    pte->page_read_bytes = page_read_bytes;
    pte->present = false;
    
    if (hash_find(&process->page_table, &pte->elem) == NULL)
        hash_insert(&process->page_table, &pte->elem);
    else free(pte);
}

void page_evict(struct process* p, void* vir_addr){
    // sometimes have bug here, but with this line is fine??? weird.
    struct page_table_entry* pte = find_pte_from_table(p, vir_addr);
    uint32_t* pd = p->thread->pagedir;
    pte->present = false;        
    pagedir_clear_page(pd, vir_addr);
}

bool load_page(struct process* p, void* vir_addr){
    vir_addr = pg_round_down(vir_addr);
    
    if (!is_user_vaddr(vir_addr)) return false;

    struct page_table_entry* pte = find_pte_from_table(p, vir_addr);
    // not found pte
    if (pte == NULL) return false;
    // pte alread present
    if (pte->present) return false;

    if (pte->phy_frame != NULL){
        // has been swapped out.
        ASSERT(pte->phy_frame->swap_pos != NOT_SWAP);
        // frame reload would reinstall all related pages.
        if (!frame_reload(pte->phy_frame))
            return false;
        return true;
    }

    struct frame* phy_frame = frame_get(p, vir_addr);
    if (phy_frame == NULL) return false;
    
    if (!load_file(pte, phy_frame) || !install_page(pte, phy_frame))
        return false;

    pte->phy_frame = phy_frame;
    pte->present = true;
    return true;
}

bool load_stack(struct process* p, void* esp, void* vir_addr){
    if (vir_addr < PHYS_BASE - STACK_PG_LIMIT * PGSIZE) return false;
    if (vir_addr <= esp - PGSIZE) return false;

    vir_addr = pg_round_down(vir_addr);
    esp = pg_round_down(esp);

    ASSERT(is_user_vaddr(vir_addr));
    ASSERT(find_pte_from_table(p, esp) == NULL);

    while (esp > vir_addr){
        pte_add(PAGE_STACK, p, NULL, esp - PGSIZE, true, 0, PGSIZE);
        if (!load_page(p, esp - PGSIZE)){
            return false;
        }

        esp -= PGSIZE;
    }
    return true;
}

void page_table_destroy(struct process* p){
    hash_destroy(&p->page_table, pte_hash_free_func);
}

static bool load_file(struct page_table_entry* pte, struct frame* phy_frame){
    if (pte->type == PAGE_FILE){
        ASSERT (pte->file != NULL);

        size_t prev_offset = file_tell(pte->file);
        file_seek(pte->file, pte->offset);
        size_t actual_read = file_read(pte->file, phy_frame->phy_addr, pte->page_read_bytes);
        if (actual_read != pte->page_read_bytes) return false;
        file_seek(pte->file, prev_offset);
    }
    memset(phy_frame->phy_addr + pte->page_read_bytes, 0, PGSIZE - pte->page_read_bytes);
    return true;
}

bool install_page(struct page_table_entry* pte, struct frame* phy_frame){
    uint32_t* pagedir = pte->process->thread->pagedir;
    if (pagedir_get_page(pagedir, pte->vir_addr) != NULL) return false;
    return pagedir_set_page(pagedir, pte->vir_addr, phy_frame->phy_addr, pte->writable);  
}

struct page_table_entry* find_pte_from_table(struct process* p, void* vir_addr){
    struct page_table_entry pte;
    pte.vir_addr = pg_round_down(vir_addr);
    struct hash_elem* elem = hash_find(&p->page_table, &pte.elem);
    if (elem == NULL) return NULL;
    return hash_entry(elem, struct page_table_entry, elem);
}

bool page_is_writable(struct process* p, void* vir_addr){
    struct page_table_entry* pte = find_pte_from_table(p, vir_addr);
    ASSERT(pte != NULL);
    return pte->writable;
}

unsigned pte_hash_hash_func(const struct hash_elem *elem, UNUSED void* aux){
    struct page_table_entry* pte = hash_entry(elem, struct page_table_entry, elem);
    return hash_int((int)pte->vir_addr);
}

bool pte_hash_less_func(const struct hash_elem *h1, const struct hash_elem *h2, UNUSED void* aux){
    struct page_table_entry* p1 = hash_entry(h1, struct page_table_entry, elem);
    struct page_table_entry* p2 = hash_entry(h2, struct page_table_entry, elem);
    return p1->vir_addr < p2->vir_addr;
}

void pte_hash_free_func(struct hash_elem *elem, UNUSED void* aux){
    struct page_table_entry* pte = hash_entry(elem, struct page_table_entry, elem);
    if (pte->phy_frame != NULL){
        pagedir_clear_page(pte->process->thread->pagedir, pte->vir_addr);
        frame_reduce_holding(pte->phy_frame, pte->process);
    }
    free(pte);
}