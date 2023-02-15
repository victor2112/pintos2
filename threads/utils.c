/* CC7-OBARRIOS
  Less functions que seran enviadas como referencia para los metodos de list sort para 
  poder ordernar las listas segun la prioridad
*/
#include "threads/utils.h"

/* CC7-OBARRIOS
  Less function para ordernar las listas por prioridad de thread
*/
bool greater_function_thread_priority(const struct list_elem* list_a, 
  const struct list_elem* list_b,
  void* aux UNUSED) { 
  return list_entry(list_a, struct thread, elem)->priority >
    list_entry(list_b, struct thread, elem)->priority;
}

/* CC7-OBARRIOS
  Less function para ordernar las listas por prioridad de lock
*/
bool greater_function_lock_priority(const struct list_elem *list_a, 
  const struct list_elem *list_b,
  void* aux UNUSED) {
  return list_entry(list_a, struct lock, lock_elem)->priority >
    list_entry(list_b, struct lock, lock_elem)->priority;
}

/* CC7-OBARRIOS
  Less function para ordernar las listas por prioridad de semaphore
*/
bool greater_function_sema_priority(const struct list_elem *list_a, 
  const struct list_elem *list_b,
  void* aux UNUSED) {
  return list_entry(list_a, struct semaphore_elem, elem)->semaphore.priority >
    list_entry(list_b, struct semaphore_elem, elem)->semaphore.priority;
}
