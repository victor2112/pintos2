#ifndef USERPROG_UTILS_H
#define USERPROG_UTILS_H

#include <stdio.h>
#include <string.h>
#include "threads/thread.h"
#include "threads/synch.h"

#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "lib/kernel/list.h"
#include "filesys/file.h"
#include "userprog/syscall.h"

char *strrev(char *str);

// CC7 - Validar la dirección
void validate_user_address (const char *addr, struct lock *memory_access_lock);

// CC7 - Obtener el segmento de la dirección
int get_user_segment (const char *addr);

// CC7 - Setea el byte en la dirección del usuario
bool put_user_segment(uint8_t *udst, uint8_t byte);

// CC7 - Validar el error de acceso a la memoria
void invalid_access(struct lock *memory_access_lock);

// CC7 - Leer la memoria y devolver los bytes
void read_memory_user_segment (void *src, void *destiny, struct lock *memory_access_lock);

// CC7 - SYSWRITE
int syscall_write(int fd, const void *buffer, unsigned size);

// CC7 - SYS_OPEN
int syscall_open(const char* filename, struct lock *memory_access_lock);

// CC7 - funcion para validar si el filedescriptor es 0, es input y 1 si es output
struct file_descriptor* file_descriptor_find(struct thread *thread, int fd);

// CC7 - SYS_READ
int syscall_read(int file_descriptor, void *buffer, int size, struct lock *memory_access_lock);

// CC7 - Implementación del SYS_EXIT
void syscall_exit(int code);

#endif /* userprog/utils.h */
