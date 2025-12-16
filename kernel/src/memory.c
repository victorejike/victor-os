#include "memory.h"

#define MEMORY_SIZE 0x1000000 // 16MB
#define BLOCK_SIZE 4096
#define BLOCKS_PER_BYTE 8

uint8_t* memory_map;
uint32_t memory_map_size;
uint32_t used_blocks;
uint32_t total_blocks;

void memory_init() {
    total_blocks = MEMORY_SIZE / BLOCK_SIZE;
    memory_map_size = total_blocks / BLOCKS_PER_BYTE;
    
    // Start memory map after kernel
    memory_map = (uint8_t*)0x100000;
    
    // Initialize all memory as free
    for(uint32_t i = 0; i < memory_map_size; i++) {
        memory_map[i] = 0;
    }
    
    // Mark first MB as used (contains kernel)
    uint32_t kernel_blocks = 0x100000 / BLOCK_SIZE;
    for(uint32_t i = 0; i < kernel_blocks; i++) {
        memory_map[i / BLOCKS_PER_BYTE] |= (1 << (i % BLOCKS_PER_BYTE));
        used_blocks++;
    }
}

static void mmap_set(int bit) {
    memory_map[bit / BLOCKS_PER_BYTE] |= (1 << (bit % BLOCKS_PER_BYTE));
}

static void mmap_unset(int bit) {
    memory_map[bit / BLOCKS_PER_BYTE] &= ~(1 << (bit % BLOCKS_PER_BYTE));
}

static int mmap_test(int bit) {
    return memory_map[bit / BLOCKS_PER_BYTE] & (1 << (bit % BLOCKS_PER_BYTE));
}

int mmap_first_free() {
    for(uint32_t i = 0; i < total_blocks; i++) {
        if(!mmap_test(i)) {
            return i;
        }
    }
    return -1;
}

int mmap_first_free_s(size_t size) {
    if(size == 0) return -1;
    
    for(uint32_t i = 0; i < total_blocks; i++) {
        if(!mmap_test(i)) {
            uint32_t free_count = 0;
            for(uint32_t j = i; j < total_blocks && free_count < size; j++) {
                if(!mmap_test(j)) {
                    free_count++;
                } else {
                    break;
                }
            }
            if(free_count >= size) {
                return i;
            }
        }
    }
    return -1;
}

void* kmalloc(size_t size) {
    if(size == 0) return NULL;
    
    // Calculate number of blocks needed
    uint32_t blocks = size / BLOCK_SIZE;
    if(size % BLOCK_SIZE != 0) blocks++;
    
    int start_block = mmap_first_free_s(blocks);
    if(start_block == -1) {
        panic("Out of memory!");
        return NULL;
    }
    
    // Mark blocks as used
    for(uint32_t i = 0; i < blocks; i++) {
        mmap_set(start_block + i);
        used_blocks++;
    }
    
    return (void*)(start_block * BLOCK_SIZE);
}

void kfree(void* ptr) {
    uint32_t block = (uint32_t)ptr / BLOCK_SIZE;
    
    // Find how many blocks are allocated
    // This is a simplified version - real implementation would track allocation sizes
    for(uint32_t i = block; i < total_blocks; i++) {
        if(mmap_test(i)) {
            mmap_unset(i);
            used_blocks--;
        } else {
            break;
        }
    }
}