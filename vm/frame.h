#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib/kernel/hash.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "vm/utils.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

struct frame_table_entry {
    void *kernel_page;
    void *frame_address;
    struct thread *owner;

    struct hash_elem hash_elem;
};

void vm_frame_init(void);
void* vm_allocate_frame(enum palloc_flags flags, uint8_t *upage);
void vm_free_frame(uint8_t *kernel_page);
void private_vm_free_frame(uint8_t *kernel_page);

#endif /* vm/frame.h */