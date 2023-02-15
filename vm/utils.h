#ifndef VM_UTILS_H
#define VM_UTILS_H

#include <stdio.h>
#include <string.h>
#include "threads/thread.h"

unsigned hash_frame_function(const struct hash_elem *elem, void *aux UNUSED);

bool less_frame_function(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

#endif /* vm/utils.h */
