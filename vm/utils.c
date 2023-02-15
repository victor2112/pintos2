#include "vm/utils.h"

// CC7 Funcion requerida para el frame_map, usaremos como key del map a kernel_page
unsigned hash_frame_function(const struct hash_elem *elem, void *aux UNUSED) {
  struct frame_table_entry *entry = hash_entry(elem, struct frame_table_entry, hash_elem);
  return hash_bytes(&entry->kernel_page, sizeof entry->kernel_page );
}

// CC7 Less function para ordernar el hash de forma ascendente
bool less_frame_function(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  return hash_entry(a, struct frame_table_entry, hash_elem)->kernel_page <
    hash_entry(b, struct frame_table_entry, hash_elem)->kernel_page;
}
