#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "threads/thread.h"

struct supplementary_page_table_entry {
    void *page_address;
    bool writeable;
    
};

#endif /* vm/page.h */