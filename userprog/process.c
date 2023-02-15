#include "userprog/process.h"

#ifndef VM
#define vm_allocate_frame(x, y) palloc_get_page(x)
#define vm_free_frame(x) palloc_free_page(x)
#endif

static thread_func start_process
NO_RETURN;

static bool load(const char *cmdline, void (**eip)(void), void **esp);

static void set_program_tokens_in_stack(char* cmdline_tokens[], int argc, void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
struct thread *
process_execute(const char *file_name) {
  const int default_pcb_value = -2;
  char *fn_copy = NULL, *temp_file = NULL;

  // CC7 - Inicializar el process control block del programa y apartamos una página
  struct process_control_block *pcb = palloc_get_page(0);
  if (pcb == NULL) {
      return NULL;
  }

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL) {
    palloc_free_page(pcb);
    return NULL;
  }

  temp_file = palloc_get_page(0);
  if (temp_file == NULL) {
    palloc_free_page(pcb);
    palloc_free_page(fn_copy);
    return NULL;
  }
    
  strlcpy(fn_copy, file_name, PGSIZE);
  strlcpy(temp_file, file_name, PGSIZE);

  //CC7 - Inicializar los valores del pcb
  // CC7 - Thread actual será  el padre del thread del pcb
  pcb->parent_thread = thread_current();

  pcb->file_name = fn_copy;
  pcb->code_exit = -1;
  pcb->is_process_waiting = false;
  pcb->is_process_finished = false;
  pcb->is_process_orphan = false;

  pcb->pid = default_pcb_value;

  sema_init(&pcb->sema_init, 0);
  sema_init(&pcb->sema_wait, 0);

  // CC7 - end inicialización pcb

  // CC7 - Formato del archivo `user_program arg1 arg2 arg3 arg4`
  // Obtendremos el program name utilizando el metodo get_program_name
  char* program_name = get_program_name(temp_file);

  /* Create a new thread to execute FILE_NAME. */
  struct thread *t = thread_create(program_name, PRI_DEFAULT, start_process, pcb);

  if (t == NULL) {
    palloc_free_page(fn_copy);
    palloc_free_page(temp_file);
    palloc_free_page(pcb);

    return NULL;
  }

  // CC7 - Esperaremos a que termine el start_process
  sema_down(&pcb->sema_init);

  palloc_free_page (fn_copy);
  palloc_free_page (temp_file);
  
  if(pcb->pid >= 0) {
      list_push_back (&(thread_current()->list_child), &(pcb->child_elem));
  } else {
    return NULL;
  }

  return t;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process(void *pcb_) {
  struct process_control_block *pcb = pcb_;
  char *file_name =  (char*) pcb->file_name;
  struct intr_frame if_;
  bool success;
  char* token;	
  char* save_ptr;	
  int cont = 0;	

  struct thread *t = thread_current();

  char **file_name_tokens = (char**) palloc_get_page(0);	
  if (file_name_tokens == NULL) {
    pcb->pid = -1;
    t->pcb = pcb;

    sema_up(&pcb->sema_init);
    
    syscall_exit(-1);
    asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
    NOT_REACHED ();
  }

  for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {	
      file_name_tokens[cont++] = token;	
  }

  /* Initialize interrupt frame and load executable. */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load(file_name_tokens[0], &if_.eip, &if_.esp);

  //validacion del load exitoso
  if (success) {
    pcb->pid = t->tid;
    set_program_tokens_in_stack(file_name_tokens, cont, &if_.esp);
  } else {
    pcb->pid = -1;
  }

  palloc_free_page(file_name_tokens);

  t->pcb = pcb;

  // CC7 - Liberamos el semáforo pa realizar el process_execute
  sema_up(&pcb->sema_init);

  if (!success){
    syscall_exit(-1);
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait(int child_id) {
  // CC7 - Procesos hijos
  struct process_control_block *pcb_children = NULL;

  // CC7 - Iterador de la lista de los threads
  struct list_elem *iterator = NULL;

  // CC7 - Obtenemos el thread actual
  struct thread *t = thread_current();

  // CC7 - Listado de threads hijos
  struct list *list_children = &(t->list_child);

  //TODO - convertir esto a metodo
  if (!list_empty(list_children)) {
      for (iterator = list_front(list_children); iterator != list_end(list_children); iterator = list_next(iterator)) {

          // CC7 - Obtenemos el process control block actual
          struct process_control_block *pcb = list_entry(iterator, struct process_control_block, child_elem);

          if(pcb->pid == child_id) {
              pcb_children = pcb;
              break;
          }
      }
  }

  // CC7 - El pcb está en waiting
  if (pcb_children == NULL || pcb_children->is_process_waiting) {
      return -1;
  }

  pcb_children->is_process_waiting = true; 

  // CC7 - Lo mandamos a que espere
  if (!pcb_children->is_process_finished) {
      sema_down(&(pcb_children->sema_wait));
  }

  // CC7 - Lanzamos un error
  ASSERT (pcb_children->is_process_finished == true);

  // CC7 - Liberamos memoria
  ASSERT (iterator != NULL);
  list_remove (iterator);

  int code_exit = pcb_children->code_exit;
  palloc_free_page(pcb_children);

  return code_exit;
}

/* Free the current process's resources. */
void
process_exit(void) {
  // TODO: Terminar este método
  struct thread *cur = thread_current();
  uint32_t *pd;

  struct list *fdlist = &cur->file_descriptors;

  // CC7 - Recorremos los file descriptors hasta realizar la accion de close
  while (!list_empty(fdlist)) {
      struct file_descriptor *file_descriptor = list_entry(list_pop_front(fdlist), 
        struct file_descriptor, 
        elem);
      file_close(file_descriptor->file);
      palloc_free_page(file_descriptor);
  }

  /*
    * CC7 - Liberamos el process control block de todos los hijos del
    * thread, si aun no poseen el estado 1(Exit) procedemos a moverlos 
    * a estado 2(Orphan) y setear el parent_thread como nulo
    */
  struct list *list_child = &cur->list_child;
  while (!list_empty(list_child)) {
      struct process_control_block *pcb = list_entry(list_pop_front(list_child), 
        struct process_control_block, 
        child_elem);

      if (pcb->is_process_finished) {
          palloc_free_page (pcb);
      } else {
          pcb->is_process_orphan = true;
          pcb->parent_thread = NULL;
      }
  }

  if(cur->executing_file) {
      file_allow_write(cur->executing_file);
      file_close(cur->executing_file);
  }

  //CC7 - Marcamos al thread como finished
  cur->pcb->is_process_finished = true;
  bool is_process_orphan = cur->pcb->is_process_orphan;

  sema_up(&cur->pcb->sema_wait);

  //CC7 - Si el thread es huerfano, liberamos el pcb
  if (is_process_orphan) {
      palloc_free_page(&cur->pcb);
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) {

    /* Correct ordering here is crucial.  We must set
       cur->pagedir to NULL before switching page directories,
       so that a timer interrupt can't switch back to the
       process page directory.  We must activate the base page
       directory before destroying the process's page
       directory, or our active page directory will be one
       that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate(void) {
  struct thread *t = thread_current();

  /* Activate thread's page tables. */
  pagedir_activate(t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
    unsigned char e_ident[16];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack(void **esp);

static bool validate_segment(const struct Elf32_Phdr *, struct file *);

static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load(const char *file_name, void (**eip)(void), void **esp) {
  struct thread *t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create();
  if (t->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof(struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
               Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE)
                          - read_bytes);
          } else {
            /* Entirely zero.
               Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void *) mem_page,
                            read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void)) ehdr.e_entry;


  // CC7 Negamos la escritura del archivo
  file_deny_write(file);
  thread_current()->executing_file = file;

  success = true;

  done:
  return success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr *phdr, struct file *file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
       We will read PAGE_READ_BYTES bytes from FILE
       and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t *kpage = vm_allocate_frame(PAL_USER, upage);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int) page_read_bytes) {
      vm_free_frame(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      vm_free_frame(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack(void **esp) {
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page(void *upage, void *kpage, bool writable) {
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pagedir, upage) == NULL
          && pagedir_set_page(t->pagedir, upage, kpage, writable));
}

/* CC7 - Obtendremos el executable name del raw filename
 *  Se espera el siguiente formato en raw_filename = `user_program arg1 arg2 arg3 arg4`
 */
char *get_program_name(char *filename) {
  char* save_ptr;
  char* program_name = strtok_r(filename, " ", &save_ptr);

  return program_name;
}

/**
 * CC7 - Nos devolverá los tokens del filename
 */ 
char ** get_program_tokens(char *filename) {
  char* token;
  char* save_ptr;
  int cont = 0;

  char **filename_tokens = NULL;

  for (token = strtok_r(filename, " ", &save_ptr); token != NULL;
        token = strtok_r(NULL, " ", &save_ptr))
  {
      filename_tokens[cont++] = token;
  }

  return filename_tokens;
}

/**
 * @brief CC7 - Seteamos lo program tokens dentro del stack
 * 
 * @param cmdline_tokens 
 * @param argc 
 * @param esp 
 */
static void
set_program_tokens_in_stack (char* cmdline_tokens[], int argc, void **esp)
{
    ASSERT(argc >= 0);
    const int BYTE_STACK = 4;

    int i, len = 0;
    void* argv_addr[argc];
    for (i = 0; i < argc; i++) {
        len = strlen(cmdline_tokens[i]) + 1;
        *esp -= len;
        memcpy(*esp, cmdline_tokens[i], len);
        argv_addr[i] = *esp;
    }

    *esp = (void*)((unsigned int)(*esp) & 0xfffffffc);

    *esp -= BYTE_STACK;
    *((uint32_t*) *esp) = 0;

    for (i = argc - 1; i >= 0; i--) {
        *esp -= BYTE_STACK;
        *((void**) *esp) = argv_addr[i];
    }

    *esp -= BYTE_STACK;
    *((void**) *esp) = (*esp + BYTE_STACK);

    *esp -= BYTE_STACK;
    *((int*) *esp) = argc;

    *esp -= BYTE_STACK;
    *((int*) *esp) = 0;

}
