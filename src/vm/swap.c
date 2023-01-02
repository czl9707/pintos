#include "vm/swap.h"
#include <bitmap.h>
#include "devices/block.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"

#define SECTOR_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

static struct block *swap_device;
static struct lock swap_device_access;
static struct bitmap *swap_usage;

void swap_init (void){
    lock_init(&swap_device_access);
    swap_device = block_get_role(BLOCK_SWAP);
    swap_usage = bitmap_create(block_size(swap_device) / SECTOR_PER_PAGE );
    if (swap_usage == NULL)
        PANIC ("Fail to create a bimap!");
}

bool swap_out (struct frame* phy_frame){
    lock_acquire(&swap_device_access);
    size_t pos = bitmap_scan_and_flip(swap_usage, 0, 1, false);
    if (pos == BITMAP_ERROR){
        lock_release(&swap_device_access);
        return false;
    }

    for (int i = 0; i < SECTOR_PER_PAGE; i ++){
        block_write(swap_device, pos * SECTOR_PER_PAGE + i,
            phy_frame->phy_addr + i * BLOCK_SECTOR_SIZE);
    }

    phy_frame->swap_pos = pos;
    palloc_free_page(phy_frame->phy_addr);
    phy_frame->phy_addr = NULL;
    lock_release(&swap_device_access);
    return true;
}

void swap_in (struct frame* phy_frame, void* phy_addr){
    ASSERT(phy_frame->swap_pos != NOT_SWAP);

    lock_acquire(&swap_device_access);
    bitmap_reset(swap_usage, phy_frame->swap_pos);

    for (int i = 0; i < SECTOR_PER_PAGE; i ++){
        block_read(swap_device, phy_frame->swap_pos * SECTOR_PER_PAGE + i,
            phy_addr + i * BLOCK_SECTOR_SIZE);
    }

    phy_frame->swap_pos = NOT_SWAP;
    phy_frame->phy_addr = phy_addr;
    lock_release(&swap_device_access);
}