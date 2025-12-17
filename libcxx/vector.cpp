#include <vector>
#include <algorithm>
#include <stdexcept>

namespace std {
    // Vector implementation
    vector_base::vector_base(size_t n)
        : _begin(nullptr), _end(nullptr), _cap_end(nullptr) {
        if(n > 0) {
            _begin = static_cast<char*>(malloc(n));
            _end = _begin;
            _cap_end = _begin + n;
        }
    }
    
    vector_base::~vector_base() {
        free(_begin);
    }
    
    // Move operations for exception safety
    void vector_base::move_from(vector_base& other) noexcept {
        _begin = other._begin;
        _end = other._end;
        _cap_end = other._cap_end;
        other._begin = other._end = other._cap_end = nullptr;
    }
}

// Specialized allocator for kernel
namespace victor {
    template<typename T>
    class kernel_allocator {
    public:
        using value_type = T;
        using size_type = size_t;
        using difference_type = ptrdiff_t;
        
        kernel_allocator() noexcept = default;
        
        template<typename U>
        kernel_allocator(const kernel_allocator<U>&) noexcept {}
        
        T* allocate(size_t n) {
            if(n > max_size()) {
                throw std::bad_alloc();
            }
            
            T* ptr = static_cast<T*>(kmalloc(n * sizeof(T)));
            if(!ptr) {
                throw std::bad_alloc();
            }
            
            return ptr;
        }
        
        void deallocate(T* p, size_t) noexcept {
            kfree(p);
        }
        
        size_t max_size() const noexcept {
            return SIZE_MAX / sizeof(T);
        }
    };
    
    // Smart pointers for kernel
    template<typename T>
    class unique_ptr {
    private:
        T* ptr;
        
    public:
        explicit unique_ptr(T* p = nullptr) : ptr(p) {}
        ~unique_ptr() { delete ptr; }
        
        // Move semantics
        unique_ptr(unique_ptr&& other) noexcept : ptr(other.ptr) {
            other.ptr = nullptr;
        }
        
        unique_ptr& operator=(unique_ptr&& other) noexcept {
            if(this != &other) {
                delete ptr;
                ptr = other.ptr;
                other.ptr = nullptr;
            }
            return *this;
        }
        
        // No copying
        unique_ptr(const unique_ptr&) = delete;
        unique_ptr& operator=(const unique_ptr&) = delete;
        
        T* operator->() const { return ptr; }
        T& operator*() const { return *ptr; }
        explicit operator bool() const { return ptr != nullptr; }
    };
}