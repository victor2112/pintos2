#include "userprog/utils.h"

//CC7 - Codigo obtenido de `https://stackoverflow.com/a/8534275` para revertir el string
char *strrev(char *str)
{
      char *p1, *p2;

      if (! str || ! *str)
            return str;
      for (p1 = str, p2 = str + strlen(str) - 1; p2 > p1; ++p1, --p2)
      {
            *p1 ^= *p2;
            *p2 ^= *p1;
            *p1 ^= *p2;
      }
      return str;
}


// CC7 - Validar si la dirección pertenece al segmento del usuario
void validate_user_address (const char *addr, struct lock *memory_access_lock) {
  if(get_user_segment(addr) == -1) {
    invalid_access(memory_access_lock);
  }
}

/* 
 * CC7 - Si ingresamos a una dirección de memoria inválida por un thread
 * que tiene el lock. Liberamos el lock y ejecutamos la salida
*/
void invalid_access(struct lock *memory_access_lock) {
  if (lock_held_by_current_thread(memory_access_lock)) {
      lock_release (memory_access_lock);
  }
    
  syscall_exit(-1);
  NOT_REACHED();
}

// CC7 - Obtener el segmento de la dirección para el usuario
int get_user_segment(const char *addr) {
  int asm_validate;

  /* CC7 - Validar que la dirección sea menor a PHYS_BASE
    Each of these functions assumes that the user address has already been verified to be below PHYS_BASE.
  */
  if (is_user_vaddr(addr)) {
      asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (asm_validate) : "m" (*addr));

      return asm_validate;
  } else {
      return -1;
  }
}

// CC7 - setea el byte en la dirección del usuario
bool put_user_segment (uint8_t *udst, uint8_t byte) {
  int error_code;

  if (!is_user_vaddr(udst)) {
    return false;
  }

  asm ("movl $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  
  return error_code != -1;
}

/**
 * CC7 - Función para devolver los bytes de la memory del usuario en el segmento dentro de la variable destiny
 */
void read_memory_user_segment(void *src, void *destiny, struct lock *memory_access_lock) {
  int segment;
  size_t i;

  for(i = 0; i < 4; i++) {
    segment = get_user_segment(src + i);
    
    if(segment == -1) {
      invalid_access(memory_access_lock);
    }

    /**
     * CC7 - Creando una máscara, operación de AND entre los bytes de segment y los bytes de ff
     * Delimitando a segment a 32 bytes -> tamaño de la arquitectura
     */
    *(char*)(destiny + i) = segment & 0xff;
  }
}

/**
 * CC7 - Implementación del Syscal Write
 * 
 */
int syscall_write(int fd, const void *buffer, unsigned size) {
  if(fd == 1) {
    putbuf(buffer, size);
    return size;
  } else {
    struct file_descriptor* file = file_descriptor_find(thread_current(), fd);
    if(file && file->file) {
      return file_write(file->file, buffer, size);
    }
  }

  return -1;
}

/**
 * CC7 - Implementación del Syscall Open
 * 
 */
int syscall_open(const char* filename, struct lock *memory_access_lock) {
  // CC7 - Archivo que esta abieto
  struct file* file_opened;

  // CC7 - Necesitaremos un espacio de memoria para cargar el archivo
  struct file_descriptor* file_descriptor = palloc_get_page(0);

  // CC7 - Nos quedamos sin memoria
  if (!file_descriptor) {
    return -1;
  }

  lock_acquire(memory_access_lock);
  file_opened = filesys_open(filename);

  // CC7 - Intentamos abrir el archivo
  if (!file_opened) {
    palloc_free_page(file_descriptor);
    lock_release(memory_access_lock);
    return -1;
  }

  file_descriptor->file = file_opened;

  // CC7 - Obtenemos el índice del nodo donde se alamacena el archivo
  struct inode *inode = file_get_inode(file_descriptor->file);

  // CC7 - Validar si logro encontrar el índice para abrirlo
  if(inode != NULL ) {
    struct inode *inode_r = inode_reopen(inode);
    file_descriptor->dir = dir_open(inode_r);
  } else {
    file_descriptor->dir = NULL;
  }

  struct list* list_file_descriptors = &thread_current()->file_descriptors;
  if (list_empty(list_file_descriptors)) {
    // TODO: Este número debe ser mayor a 2
    file_descriptor->id = 3;
  } else {
    file_descriptor->id = (list_entry(list_back(list_file_descriptors), 
      struct file_descriptor, elem)->id) + 1;
  }

  list_push_back(list_file_descriptors, &(file_descriptor->elem));
  lock_release (memory_access_lock);

  return file_descriptor->id;
}

/**
 * @brief CC7 - Validar si el file descriptor es input u output
 * 
 * @param thread 
 * @param fd 
 * @return struct file_descriptor* 
 */
struct file_descriptor*
file_descriptor_find(struct thread *thread, int fd) {
  ASSERT (thread != NULL);
  
  if (fd < 2) {
    return NULL;
  }

  struct list_elem *element; 

  // CC7 - Recorrer la lista de file_descriptors
  if (! list_empty(&thread->file_descriptors)) {
    for(element = list_begin(&thread->file_descriptors);
        element != list_end(&thread->file_descriptors); element = list_next(element))
    {
      struct file_descriptor *desc = list_entry(element, struct file_descriptor, elem);

      // CC7 - Retornar el file descriptor que encuentra en la lista
      if(desc->id == fd) {
        return desc;
      }
    }
  }

  return NULL;
}

/**
 * @brief CC7 - Implementación de syscall read
 * 
 * @param file_descriptor 
 * @param buffer 
 * @param size 
 * @param memory_access_lock 
 * @return int 
 */
int syscall_read(int file_descriptor, void *buffer, int size, struct lock *memory_access_lock)
{
  // CC7 - Si el file_descriptor es un input
  if (file_descriptor == 0) {
    for (int i = 0; i < size; i++) {
      if (!put_user_segment(buffer + i, input_getc())) {
        lock_release(memory_access_lock);
        syscall_exit(-1);
      }
    }
    return size;
  } else {
     struct file_descriptor* fd = file_descriptor_find(thread_current(), file_descriptor);
     if (fd && fd->file) {
       return file_read(fd->file, buffer, size);
     }
  }
     
  return -1;
}

void
syscall_exit(int code) {
  printf("%s: exit(%d)\n", thread_current()->name, code);
  struct process_control_block *process_control_block = thread_current()->pcb;

  if (process_control_block != NULL) {
    process_control_block->code_exit = code;
  }

  thread_exit();
}