#include <arch/user_mode.h>
#include <process/process.h>
#include <syscall/syscall.h>

namespace arch {
    
// User mode context
class user_context {
private:
    // Saved registers
    struct registers {
        uint64_t rax, rbx, rcx, rdx;
        uint64_t rsi, rdi, rbp, rsp;
        uint64_t r8, r9, r10, r11;
        uint64_t r12, r13, r14, r15;
        uint64_t rip, rflags;
        uint64_t cs, ss, ds, es, fs, gs;
    } regs;
    
    // FPU/SSE state
    fpu_state_t fpu;
    
    // Debug registers
    dr_regs_t debug;
    
public:
    // Save current context
    void save() {
        // Save general registers
        asm volatile(
            "mov %%rax, %0\n"
            "mov %%rbx, %1\n"
            "mov %%rcx, %2\n"
            "mov %%rdx, %3\n"
            : "=m"(regs.rax), "=m"(regs.rbx),
              "=m"(regs.rcx), "=m"(regs.rdx)
        );
        
        // Save remaining registers
        asm volatile(
            "mov %%rsi, %0\n"
            "mov %%rdi, %1\n"
            "mov %%rbp, %2\n"
            "mov %%rsp, %3\n"
            : "=m"(regs.rsi), "=m"(regs.rdi),
              "=m"(regs.rbp), "=m"(regs.rsp)
        );
        
        // Save segment registers
        asm volatile("mov %%cs, %0" : "=m"(regs.cs));
        asm volatile("mov %%ss, %0" : "=m"(regs.ss));
        
        // Save control registers
        asm volatile("pushfq\npop %0" : "=m"(regs.rflags));
        
        // Save FPU state
        fpu_save(&fpu);
        
        // Save debug registers
        debug_save(&debug);
    }
    
    // Restore context
    void restore() {
        // Restore segment registers first
        load_segment_registers();
        
        // Restore general registers
        asm volatile(
            "mov %0, %%rax\n"
            "mov %1, %%rbx\n"
            "mov %2, %%rcx\n"
            "mov %3, %%rdx\n"
            : : "m"(regs.rax), "m"(regs.rbx),
                "m"(regs.rcx), "m"(regs.rdx)
        );
        
        // Restore stack pointer
        asm volatile("mov %0, %%rsp" : : "m"(regs.rsp));
        
        // Restore FPU state
        fpu_restore(&fpu);
        
        // Restore debug registers
        debug_restore(&debug);
        
        // Return to user mode
        iret_to_user();
    }
    
    // Switch to user mode
    void switch_to_user(uintptr_t entry, uintptr_t stack) {
        // Set up user mode segments
        regs.cs = USER_CS | 3;    // Ring 3
        regs.ss = USER_DS | 3;    // Ring 3
        
        // Set entry point and stack
        regs.rip = entry;
        regs.rsp = stack;
        
        // Enable interrupts in user mode
        regs.rflags = 0x200;      // IF flag
        
        // Clear other registers
        regs.rax = regs.rbx = regs.rcx = regs.rdx = 0;
        regs.rsi = regs.rdi = regs.rbp = 0;
        
        // Switch to user mode
        restore();
    }
};

// Process creation with privilege separation
process_t* create_user_process(const char* path, 
                               const char* const argv[],
                               const char* const envp[]) {
    // Load ELF executable
    elf_info_t elf;
    if(!load_elf(path, &elf)) {
        return nullptr;
    }
    
    // Create address space
    address_space_t* as = create_address_space();
    
    // Set up user memory layout
    setup_user_memory_layout(as, &elf);
    
    // Create initial thread
    thread_t* thread = create_thread();
    
    // Set up user stack
    uintptr_t stack_top = setup_user_stack(as, argv, envp);
    
    // Create process
    process_t* proc = new process_t();
    proc->pid = allocate_pid();
    proc->address_space = as;
    proc->main_thread = thread;
    proc->state = PROCESS_RUNNING;
    
    // Set credentials
    proc->cred.uid = get_current_uid();
    proc->cred.gid = get_current_gid();
    proc->cred.euid = proc->cred.uid;
    proc->cred.egid = proc->cred.gid;
    
    // Copy command line
    proc->name = strdup(path);
    
    // Initialize thread context
    thread->context.switch_to_user(elf.entry, stack_top);
    
    // Add to process table
    add_process(proc);
    
    return proc;
}

// System call handler
uint64_t handle_syscall(syscall_number_t nr,
                       uint64_t a1, uint64_t a2, uint64_t a3,
                       uint64_t a4, uint64_t a5, uint64_t a6) {
    // Validate system call number
    if(nr >= MAX_SYSCALLS) {
        return -ENOSYS;
    }
    
    // Get current process
    process_t* proc = get_current_process();
    
    // Check permissions for this syscall
    if(!check_syscall_permission(proc, nr)) {
        return -EPERM;
    }
    
    // Dispatch system call
    switch(nr) {
        case SYS_READ:
            return sys_read(a1, (void*)a2, a3);
            
        case SYS_WRITE:
            return sys_write(a1, (const void*)a2, a3);
            
        case SYS_OPEN:
            return sys_open((const char*)a1, a2, a3);
            
        case SYS_CLOSE:
            return sys_close(a1);
            
        case SYS_FORK:
            return sys_fork();
            
        case SYS_EXECVE:
            return sys_execve((const char*)a1, 
                            (char* const*)a2, 
                            (char* const*)a3);
            
        case SYS_WAITPID:
            return sys_waitpid(a1, (int*)a2, a3);
            
        case SYS_BRK:
            return sys_brk((void*)a1);
            
        case SYS_MMAP:
            return sys_mmap((void*)a1, a2, a3, a4, a5, a6);
            
        case SYS_MUNMAP:
            return sys_munmap((void*)a1, a2);
            
        case SYS_IOCTL:
            return sys_ioctl(a1, a2, (void*)a3);
            
        case SYS_SOCKET:
            return sys_socket(a1, a2, a3);
            
        case SYS_CONNECT:
            return sys_connect(a1, (const sockaddr*)a2, a3);
            
        // ... more system calls
            
        default:
            return -ENOSYS;
    }
}

// Capability-based security
class capabilities {
private:
    // Capability set
    cap_set_t caps;
    
public:
    capabilities() {
        // Start with no capabilities
        cap_clear_all(&caps);
    }
    
    // Check if process has capability
    bool has_capability(capability_t cap) {
        return cap_is_set(&caps, cap);
    }
    
    // Grant capability
    void grant(capability_t cap) {
        cap_set(&caps, cap);
    }
    
    // Revoke capability
    void revoke(capability_t cap) {
        cap_clear(&caps, cap);
    }
    
    // Check if subset of capabilities
    bool is_subset(const capabilities& other) {
        return cap_is_subset(&caps, &other.caps);
    }
};

// Secure Computing (seccomp)
class seccomp_filter {
private:
    struct sock_filter program[MAX_FILTER_LEN];
    size_t len;
    
public:
    seccomp_filter() : len(0) {}
    
    // Add rule to filter
    void add_rule(uint32_t syscall_nr, uint32_t action) {
        if(len >= MAX_FILTER_LEN - 2) {
            return;
        }
        
        // Load syscall number
        program[len++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                 offsetof(seccomp_data, nr));
        
        // Compare with desired syscall
        program[len++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                 syscall_nr, 0, 1);
        
        // Return action
        program[len++] = BPF_STMT(BPF_RET | BPF_K, action);
    }
    
    // Install filter
    bool install() {
        struct sock_fprog prog = {
            .len = (unsigned short)len,
            .filter = program
        };
        
        return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == 0;
    }
};

} // namespace arch