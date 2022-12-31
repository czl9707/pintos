#include "vm/frame.h"
#include <stdio.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "vm/page.h"

static struct list all_frames;
static struct lock all_frames_access;
static struct list_elem *clock_hand, *all_frames_end;

static struct frame* frame_add(void* phy_addr, struct process* p, void* vir_addr);
static struct frame* frame_find(void* phy_addr) UNUSED;
static void frame_remove(struct frame*);
static bool frame_try_evict(void);
static struct frame* frame_get_eviction(void);
static bool frame_evict(struct frame* phy_frame);
static bool frame_set_bit_if_accessed(struct frame* phy_frame);
static bool frame_is_evictable(struct frame* phy_frame);

struct process_upage_wrapper {
    struct list_elem elem;
    struct process* p;
    void* vir_addr;
};

void frame_init(void){
    list_init(&all_frames);
    lock_init(&all_frames_access);
    clock_hand = list_end(&all_frames);
    all_frames_end = list_end(&all_frames);
}

struct frame* frame_get(struct process* p, void* vir_addr){
    void* phy_addr = palloc_get_page(PAL_USER);
    if (phy_addr == NULL){
        if (frame_try_evict()){
            phy_addr = palloc_get_page(PAL_USER);
        }else{
            PANIC("Unable to get frame, all frames occupied, no swap slot available.");
        }
    }
    
    return frame_add(phy_addr, p, vir_addr);
}

bool frame_reload(struct frame* phy_frame){
    lock_acquire(&phy_frame->holding_access);

    void* phy_addr = palloc_get_page(PAL_USER);
    if (phy_addr == NULL){
        if (frame_try_evict()){
            phy_addr = palloc_get_page(PAL_USER);
        }else{
            PANIC("Unable to get frame, all frames occupied, no swap slot available.");
        }
    }
    
    swap_in(phy_frame, phy_addr);
    
    struct process_upage_wrapper* p_wrapper;
    struct list_elem *elem, *end = list_end(&phy_frame->holding);
    for (elem = list_begin(&phy_frame->holding); elem != end; elem = list_next(elem)){
        p_wrapper = list_entry(elem, struct process_upage_wrapper, elem);
        if (!install_page(
            find_pte_from_table(p_wrapper->p, p_wrapper->vir_addr),
            phy_frame
        )){
            lock_release(&phy_frame->holding_access);
            return false;
        }
    }
    
    lock_release(&phy_frame->holding_access);

    return true;
}

void frame_reduce_holding(struct frame* phy_frame, struct process* p){
    struct process_upage_wrapper *iter, *result = NULL;

    lock_acquire(&phy_frame->holding_access);
    struct list_elem *elem, *end = list_end(&phy_frame->holding);
    for (elem = list_begin(&phy_frame->holding); elem != end; elem = list_next(elem)){
        iter = list_entry(elem, struct process_upage_wrapper, elem);
        if (iter->p == p){
            result = iter;
            break;
        }
    }

    ASSERT(result != NULL);
    list_remove(&result->elem);
    lock_release(&phy_frame->holding_access);
    free(result);

    if (list_empty(&phy_frame->holding)) 
        frame_remove(phy_frame);
}

static bool frame_try_evict(void){
    bool evict_success;

    lock_acquire(&all_frames_access);
    struct frame* f_eviction = frame_get_eviction();
    evict_success = frame_evict(f_eviction);
    lock_release(&all_frames_access);

    return evict_success;
}

static struct frame* frame_add(void* phy_addr, struct process* p, void* vir_addr){
    struct frame* f = malloc(sizeof(struct frame));
    f->phy_addr = phy_addr;
    f->swap_pos = NOT_SWAP;
    list_init(&f->holding);
    lock_init(&f->holding_access);
    
    struct process_upage_wrapper* p_wrapper = malloc(sizeof(struct process_upage_wrapper));
    p_wrapper->p = p;
    p_wrapper->vir_addr = vir_addr;
    lock_acquire(&f->holding_access);
    list_push_back(&f->holding, &p_wrapper->elem);
    lock_release(&f->holding_access);

    lock_acquire(&all_frames_access);
    list_push_back(&all_frames, &f->elem);
    lock_release(&all_frames_access);
    return f;
}

// all_frames_access lock should be acquired before this function called.
static struct frame* frame_get_eviction(void){
    struct frame *f;

    while (true){
        if (clock_hand == all_frames_end){
            clock_hand = list_begin(&all_frames);
        }
        f = list_entry(clock_hand, struct frame, elem);
        if (frame_is_evictable(f)){
            if (frame_set_bit_if_accessed(f)){
                clock_hand = list_next(clock_hand);
                return f;
            }
        }

        clock_hand = list_next(clock_hand);
    }
}

// all_frames_access lock should be acquired before this function called.
// return false if is accessed, true not accessed
static bool frame_set_bit_if_accessed(struct frame* phy_frame){
    bool accessed = false;
    struct process_upage_wrapper *p_wrapper;

    lock_acquire(&phy_frame->holding_access);
    struct list_elem *elem, *end = list_end(&phy_frame->holding);
    
    for (elem = list_begin(&phy_frame->holding); elem != end; elem = list_next(elem)){
        p_wrapper = list_entry(elem, struct process_upage_wrapper, elem);
        uint32_t* pd = p_wrapper->p->thread->pagedir;
        accessed |= pagedir_is_accessed(pd, p_wrapper->vir_addr);
        pagedir_set_accessed(pd, p_wrapper->vir_addr, false);
    }

    lock_release(&phy_frame->holding_access);

    return accessed;
}

static bool frame_evict(UNUSED struct frame* phy_frame){
    struct process_upage_wrapper *p_wrapper;

    lock_acquire(&phy_frame->holding_access);
    struct list_elem *elem, *end = list_end(&phy_frame->holding);

    for (elem = list_begin(&phy_frame->holding); elem != end; elem = list_next(elem)){
        p_wrapper = list_entry(elem, struct process_upage_wrapper, elem);
        page_evict(p_wrapper->p, p_wrapper->vir_addr);
    }

    lock_release(&phy_frame->holding_access);

    return swap_out(phy_frame);
}

static struct frame* frame_find(void* phy_addr){    
    struct frame *f, *result = NULL;

    lock_acquire(&all_frames_access);
    struct list_elem *elem, *end = list_end(&all_frames);
    for (elem = list_begin(&all_frames); elem != end; elem = list_next(elem)){
        f = list_entry(elem, struct frame, elem);
        if (f->phy_addr == phy_addr){
            result = f;
            break;
        }
    }
    lock_release(&all_frames_access);
    
    return result;
}

static void frame_remove(struct frame* phy_frame){
    palloc_free_page(phy_frame->phy_addr);
    lock_acquire(&all_frames_access);
    list_remove(&phy_frame->elem);
    lock_release(&all_frames_access);
    // lock_acquire(&phy_frame->holding_access);
    free(phy_frame);
}

static bool frame_is_evictable(struct frame* phy_frame){
    // ASSERT(!list_empty(&phy_frame->holding))
    // struct list_elem *elem = list_begin(&phy_frame->holding);
    // struct page_table_entry* pte = list_entry(elem, struct page_table_entry, elem);

    return phy_frame->swap_pos == NOT_SWAP;
}