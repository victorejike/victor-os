#include <cxxabi.h>
#include <new>
#include <exception>

// Global new/delete operators
void* operator new(size_t size) {
    void* ptr = malloc(size);
    if(!ptr && size > 0) {
        throw std::bad_alloc();
    }
    return ptr;
}

void* operator new[](size_t size) {
    return operator new(size);
}

void* operator new(size_t size, std::nothrow_t) noexcept {
    return malloc(size);
}

void* operator new[](size_t size, std::nothrow_t) noexcept {
    return malloc(size);
}

void operator delete(void* ptr) noexcept {
    free(ptr);
}

void operator delete[](void* ptr) noexcept {
    free(ptr);
}

void operator delete(void* ptr, size_t) noexcept {
    free(ptr);
}

void operator delete[](void* ptr, size_t) noexcept {
    free(ptr);
}

// Exception handling personality function
extern "C" void __cxa_pure_virtual() {
    // Pure virtual function called
    panic("Pure virtual function called!");
}

namespace __cxxabiv1 {
    // Type info for basic types
    __class_type_info::~__class_type_info() {}
    
    // Exception handling
    void terminate() noexcept {
        // Call terminate handler
        std::terminate_handler handler = std::get_terminate();
        if(handler) handler();
        
        // If handler returns, abort
        abort();
    }
}

// RTTI support
void* __dynamic_cast(const void* sub, 
                     const __class_type_info* src,
                     const __class_type_info* dst,
                     ptrdiff_t src2dst_offset) {
    // Simplified dynamic_cast implementation
    if(!sub) return nullptr;
    
    // Check if types match
    if(src == dst) return const_cast<void*>(sub);
    
    // Traverse class hierarchy (simplified)
    // In real implementation, traverse vtable
    return nullptr;
}

// Thread-safe static initialization
static int __cxa_guard_acquire(uint64_t* guard_object) {
    // Simplified guard implementation
    if((*guard_object & 0x1) == 0) {
        if(__sync_bool_compare_and_swap(guard_object, 0, 1)) {
            return 1; // Need to run constructor
        }
    }
    return 0; // Already initialized
}

void __cxa_guard_release(uint64_t* guard_object) {
    __sync_and_and_fetch(guard_object, ~0x1);
    __sync_or_and_fetch(guard_object, 0x2);
}

void __cxa_guard_abort(uint64_t* guard_object) {
    __sync_and_and_fetch(guard_object, 0);
}

// Unwind support for exceptions
_Unwind_Reason_Code __gxx_personality_v0(
    int version,
    _Unwind_Action actions,
    uint64_t exceptionClass,
    _Unwind_Exception* unwind_exception,
    _Unwind_Context* context) {
    
    // Simplified personality function
    if(actions & _UA_SEARCH_PHASE) {
        return _URC_HANDLER_FOUND;
    }
    
    if(actions & _UA_CLEANUP_PHASE) {
        // Run destructors
        return _URC_INSTALL_CONTEXT;
    }
    
    return _URC_CONTINUE_UNWIND;
}

// Support for thread-local storage
void* __tls_get_addr(size_t offset) {
    // Get thread-local storage pointer
    thread_control_block_t* tcb = get_current_tcb();
    return (void*)((uintptr_t)tcb->tls_base + offset);
}