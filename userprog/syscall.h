#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/kernel/list.h"
#include "threads/synch.h"

void syscall_init (void);

/**
 * CC7 - Estructura para manejar un archivo
 * 
 */
struct file_descriptor {
    int id;
    // CC7 - Listado de los threads de ejecución
    struct list_elem elem;

    struct file* file;

    // CC7 - Almacenaremos la dirección del directorio del archivo
    struct dir* dir;
};

/**
 * @brief CC7 - Estructura para manejar el Process Control Block
 * 
 */
struct process_control_block {

    // CC7 - id del pcb
    int pid;         

    // CC7 - Nombre del archivo    
    const char* file_name;

    // CC7 - lista de hijos
    struct list_elem child_elem;

    // CC7 - Thread Padre
    struct thread* parent_thread;

    // CC7 - Semáforo utilizado para la sincronización (creación de pcb)
    struct semaphore sema_init;

    // CC7 - Semáforo utilizado para el waiting
    struct semaphore sema_wait;

    bool is_process_waiting;
    bool is_process_finished;
    bool is_process_orphan;

    // CC7 - Código de salida
    int code_exit;
};

#endif /* userprog/syscall.h */
