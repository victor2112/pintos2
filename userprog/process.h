#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/utils.h"
#include "userprog/syscall.h"
#include "vm/frame.h"


struct thread * process_execute(const char *file_name);
int process_wait(int child_id);
void process_exit(void);
void process_activate(void);
char **get_program_tokens(char *raw_filename);

char *get_program_name(char *raw_filename);

#endif /* userprog/process.h */