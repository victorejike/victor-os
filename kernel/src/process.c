#include "process.h"

#define MAX_PROCESSES 64
#define PROCESS_STACK_SIZE 4096

process_t processes[MAX_PROCESSES];
uint32_t next_pid = 1;

void process_init() {
    for(int i = 0; i < MAX_PROCESSES; i++) {
        processes[i].pid = 0;
        processes[i].state = PROCESS_UNUSED;
    }
    
    // Create kernel idle process
    process_t* idle = process_create(NULL, 0);
    idle->state = PROCESS_RUNNING;
    idle->name = "idle";
}

process_t* process_create(void* entry_point, uint32_t flags) {
    for(int i = 0; i < MAX_PROCESSES; i++) {
        if(processes[i].state == PROCESS_UNUSED) {
            process_t* proc = &processes[i];
            
            // Allocate stack
            proc->stack = kmalloc(PROCESS_STACK_SIZE);
            if(!proc->stack) return NULL;
            
            // Initialize process
            proc->pid = next_pid++;
            proc->state = PROCESS_READY;
            proc->flags = flags;
            proc->regs.eip = (uint32_t)entry_point;
            proc->regs.esp = (uint32_t)proc->stack + PROCESS_STACK_SIZE;
            proc->regs.ebp = proc->regs.esp;
            
            // Set up kernel stack
            proc->kstack = kmalloc(PROCESS_STACK_SIZE);
            proc->regs.ss0 = 0x10;
            proc->regs.esp0 = (uint32_t)proc->kstack + PROCESS_STACK_SIZE;
            
            return proc;
        }
    }
    return NULL;
}

void process_schedule() {
    static int current = 0;
    
    // Find next ready process
    int next = -1;
    for(int i = 1; i < MAX_PROCESSES; i++) {
        int idx = (current + i) % MAX_PROCESSES;
        if(processes[idx].state == PROCESS_READY) {
            next = idx;
            break;
        }
    }
    
    if(next == -1) {
        // No processes ready, run idle
        for(int i = 0; i < MAX_PROCESSES; i++) {
            if(strcmp(processes[i].name, "idle") == 0) {
                next = i;
                break;
            }
        }
    }
    
    if(next != -1 && next != current) {
        process_switch(&processes[current], &processes[next]);
        current = next;
    }
}

void process_switch(process_t* from, process_t* to) {
    if(from == to) return;
    
    // Save current process state
    asm volatile(
        "pusha\n"
        "push %%ds\n"
        "push %%es\n"
        "push %%fs\n"
        "push %%gs\n"
        "mov %%esp, %0\n"
        : "=m"(from->regs.esp)
    );
    
    // Load new process state
    asm volatile(
        "mov %0, %%esp\n"
        "pop %%gs\n"
        "pop %%fs\n"
        "pop %%es\n"
        "pop %%ds\n"
        "popa\n"
        "iret\n"
        : : "m"(to->regs.esp)
    );
}