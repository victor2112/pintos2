#ifndef THREADS_UTILS_H
#define THREADS_UTILS_H

#include <stdio.h>
#include <string.h>
#include "threads/thread.h"
#include "threads/synch.h"

bool greater_function_thread_priority(const struct list_elem* list_a, 
  const struct list_elem* list_b,
  void* aux UNUSED);

bool greater_function_lock_priority(const struct list_elem *list_a, 
  const struct list_elem *list_b,
  void* aux UNUSED);

bool greater_function_sema_priority(const struct list_elem *list_a, 
  const struct list_elem *list_b,
  void* aux UNUSED);

#endif /* threads/utils.h */
