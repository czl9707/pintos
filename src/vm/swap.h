#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "vm/page.h"
#include "vm/frame.h"

void swap_init(void);
bool swap_out (struct frame* phy_frame);
void swap_in (struct frame* phy_frame, void* phy_addr);

#endif /* vm/swap.h */