#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "userprog/process.h"
#include "devices/block.h"

#define NOT_SWAP SIZE_MAX

struct frame {
    struct list_elem elem;              /**< Keep track of all frames. */
    struct list holding;                /**< Process holding the frame. */
    struct lock holding_access;         /**< Access holding list. */
    
    void *phy_addr;                     /**< Physical Address. */
    size_t swap_pos;                    /**< Record the pos of swap_device, if not swap yet UINT32_MAX */
};  

void frame_init (void);
struct frame* frame_get(struct process* p, void* vir_addr);
bool frame_reload(struct frame* phy_frame);
void frame_reduce_holding(struct frame* phy_frame, struct process* p);

#endif /**< vm/frame.h */