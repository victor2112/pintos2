#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

// CC7 - Importar funciones genéricas
#include "userprog/utils.h"

static void syscall_handler (struct intr_frame *);

//CC7 - Lock de acceso a memoria
struct lock memory_access_lock;

void
syscall_init (void) 
{
  lock_init(&memory_access_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{

  // CC7 - Finalizar el thread
  if(f->esp == NULL) {
    thread_exit();
  }

  // CC7 - Variable del número de syscall
  int syscall;

  // CC7 - Asignar a syscall lo que está en el puntero de esp
  read_memory_user_segment(f->esp, &syscall, &memory_access_lock);

  switch(syscall)
  {
    case SYS_HALT:
    {
      // Implement syscall HALT
      // CC7 - Llamada a la función shutdown_power_off
      shutdown_power_off();

      break;
    }
    case SYS_EXIT:
    {
      int code;
      // Implement syscall EXIT
      read_memory_user_segment(f->esp + 4, &code, &memory_access_lock);

      // CC7 - Finalizar el thread
      syscall_exit(code);
      NOT_REACHED();
      break;
    }
    case SYS_EXEC:
    {
      // Implement syscall EXEC
      void* cmdline;
      int return_code;

      read_memory_user_segment(f->esp + 4, &cmdline, &memory_access_lock);
      validate_user_address((const char*) cmdline, &memory_access_lock);

      lock_acquire (&memory_access_lock);
      struct thread* thread = process_execute(cmdline);
      lock_release (&memory_access_lock);

      // CC7 - obtenemos el id del pcb del thread

      if (thread == NULL) {
       return_code = -1;
      } else {
       return_code = thread->pcb->pid;
      }

      f->eax = (uint32_t) return_code;
      
      break;
    }
    case SYS_WAIT:
    {
      // Implement syscall WAIT
      int pid;
      read_memory_user_segment(f->esp + 4, &pid, &memory_access_lock);

      f->eax = process_wait(pid);

      break;
    }
     case SYS_CREATE:
    {
      // Implement syscall CREATE
      const char* filename;
      unsigned initial_size;

      read_memory_user_segment(f->esp + 4, &filename, &memory_access_lock);
      read_memory_user_segment(f->esp + 8, &initial_size, &memory_access_lock);

      validate_user_address(filename, &memory_access_lock);

      lock_acquire(&memory_access_lock);
      f->eax = filesys_create(filename, initial_size);
      lock_release(&memory_access_lock);

      break;
    }
    case SYS_WRITE:
    {
      // Implement syscall WRITE
      int fd;
      const void *buffer;
      unsigned size;

      read_memory_user_segment(f->esp + 4, &fd, &memory_access_lock);
      
      read_memory_user_segment(f->esp + 8, &buffer, &memory_access_lock);
      validate_user_address((const char*) buffer, &memory_access_lock);

      read_memory_user_segment(f->esp + 12, &size, &memory_access_lock);
      validate_user_address((const char*) buffer + size - 1, &memory_access_lock);

      lock_acquire(&memory_access_lock);
      f->eax = syscall_write(fd, buffer, size);
      lock_release(&memory_access_lock);

      break;
    }
    case SYS_REMOVE:
    {
      // Implement syscall SYS_REMOVE
      const char* filename;

      read_memory_user_segment(f->esp + 4, &filename, &memory_access_lock);
      validate_user_address(filename, &memory_access_lock);

      lock_acquire (&memory_access_lock);
      f->eax = (int) filesys_remove(filename);
      lock_release (&memory_access_lock);

      break;

    }
    case SYS_OPEN:
    {
      // Implement syscall SYS_OPEN
      const char* filename;

      read_memory_user_segment(f->esp + 4, &filename, &memory_access_lock);
      validate_user_address(filename, &memory_access_lock);

      f->eax = syscall_open(filename, &memory_access_lock);
      break;

    }
    case SYS_FILESIZE:
    {
      // Implement syscall SYS_FILESIZE
      int file_descriptor;
      struct file_descriptor* fd;

      read_memory_user_segment(f->esp + 4, &file_descriptor, &memory_access_lock);

      lock_acquire (&memory_access_lock);

      fd = file_descriptor_find(thread_current(), file_descriptor);
      if (fd == NULL) {
        lock_release(&memory_access_lock);
        f->eax = -1;
        break;
      }

      f->eax = file_length(fd->file);
      lock_release (&memory_access_lock);

      break;
    }
    case SYS_READ:
    {
      // Implement syscall SYS_READ
      int file_descriptor;
      void *buffer;
      int size;

      read_memory_user_segment(f->esp + 4, &file_descriptor, &memory_access_lock);
      
      read_memory_user_segment(f->esp + 8, &buffer, &memory_access_lock);
      validate_user_address((const char*) buffer, &memory_access_lock);

      read_memory_user_segment(f->esp + 12, &size, &memory_access_lock);
      validate_user_address((const char*) buffer + size - 1, &memory_access_lock);

      lock_acquire(&memory_access_lock);
      f->eax = (int) syscall_read(file_descriptor, buffer, size, &memory_access_lock);
      lock_release(&memory_access_lock);

      break;
    }
    case SYS_SEEK:
    {
      // Implement syscall SYS_SEEK
      int file_descriptor;
      int pos;

      read_memory_user_segment(f->esp + 4, &file_descriptor, &memory_access_lock);
      read_memory_user_segment(f->esp + 8, &pos, &memory_access_lock);

      lock_acquire(&memory_access_lock);

      struct file_descriptor* fd = file_descriptor_find(thread_current(), file_descriptor);
      // CC7 - Validar si existe el archivo en el file_descriptor
      if (fd && fd->file) {
        // CC7 - establecer la posición actual en el file
        file_seek(fd->file, pos);
      }
      
      lock_release(&memory_access_lock);

      break;

    }
    case SYS_TELL:
    {
      // Implement syscall SYS_TELL
      int file_descriptor;

      read_memory_user_segment(f->esp + 4, &file_descriptor, &memory_access_lock);

      lock_acquire(&memory_access_lock);

      struct file_descriptor* fd = file_descriptor_find(thread_current(), file_descriptor);
      // CC7 - Retornamos la posición actual del file
      if (fd && fd->file) {
        f->eax = (int) file_tell(fd->file);
      } else {
        f->eax = -1;
      }

      lock_release(&memory_access_lock);
      break;
    }
    case SYS_CLOSE:
    {
      // Implement syscall SYS_CLOSE
      int file_descriptor;

      read_memory_user_segment(f->esp + 4, &file_descriptor, &memory_access_lock);

      lock_acquire(&memory_access_lock);

      struct file_descriptor* fd = file_descriptor_find(thread_current(), file_descriptor);
      // CC7 - Obtenemos el filedescriptor y cerramos el archivo
      if(fd && fd->file) {
        file_close(fd->file);

        if(fd->dir) {
          dir_close(fd->dir);
        }

        list_remove(&(fd->elem));
        palloc_free_page(fd);
      }

      lock_release (&memory_access_lock);

      break;
    }
    default: {
      syscall_exit(-1);
      break;
    }
  }
}
