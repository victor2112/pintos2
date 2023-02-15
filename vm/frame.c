#include "vm/frame.h"

static struct lock frame_lock;
static struct hash frame_mapping;

void vm_frame_init(void) {
  lock_init(&frame_lock);
  hash_init(&frame_mapping, &hash_frame_function, &less_frame_function, NULL);
}

void* vm_allocate_frame(enum palloc_flags flags, uint8_t *upage) {
    lock_acquire(&frame_lock);

    void *frame_page = palloc_get_page(PAL_USER | flags);
    /*if (frame_page == NULL) {
      struct frame_table_entry *f_evicted = pick_frame_to_evict(thread_current()->pagedir);

      ASSERT(f_evicted != NULL && f_evicted->t != NULL);
      ASSERT(f_evicted->t->pagedir != (void*)0xcccccccc);

      pagedir_clear_page(f_evicted->t->pagedir, f_evicted->upage);

      bool is_dirty = false;
      is_dirty = is_dirty || pagedir_is_dirty(f_evicted->t->pagedir, f_evicted->upage);
      is_dirty = is_dirty || pagedir_is_dirty(f_evicted->t->pagedir, f_evicted->kpage);

      swap_index_t swap_idx = vm_swap_out(f_evicted->kpage);
      vm_supt_set_swap(f_evicted->t->supt, f_evicted->upage, swap_idx);
      vm_supt_set_dirty(f_evicted->t->supt, f_evicted->upage, is_dirty);
      vm_frame_do_free(f_evicted->kernel_page, true);

      frame_page = palloc_get_page(PAL_USER | flags);
      ASSERT(frame_page != NULL);
    }*/

    struct frame_table_entry *frame = malloc(sizeof(struct frame_table_entry));
    if (frame == NULL) {
      lock_release(&frame_lock);
      return NULL;
    }

    frame->owner = thread_current();
    frame->frame_address = frame_page;

    hash_insert(&frame_mapping, &frame->hash_elem);

    lock_release (&frame_lock);
    return frame_page;
}

void vm_free_frame(uint8_t *kernel_page) {
  lock_acquire(&frame_lock);
  
  private_vm_free_frame(kernel_page);
  palloc_free_page(kernel_page);

  lock_release(&frame_lock);
}

void private_vm_free_frame(uint8_t *kernel_page) {
  ASSERT (lock_held_by_current_thread(&frame_lock) == true);
  ASSERT (is_kernel_vaddr(kernel_page));
  //ASSERT (pg_ofs (kernel_page) == 0);

  struct frame_table_entry f_tmp;
  f_tmp.kernel_page = kernel_page;

  struct hash_elem *hash = hash_find(&frame_mapping, &(f_tmp.hash_elem));
  if (hash == NULL) {
    PANIC ("The page to be freed is not stored in the table");
  }

  struct frame_table_entry *frame = hash_entry(hash, struct frame_table_entry, hash_elem);

  hash_delete(&frame_mapping, &frame->hash_elem);

  free(frame);
}