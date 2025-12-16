#include "victorfs.h"

#define VICTORFS_MAGIC 0x56494354 // 'VICT'
#define MAX_FILES 256
#define BLOCK_SIZE 512

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t block_count;
    uint32_t free_blocks;
    uint32_t root_dir;
    uint32_t checksum;
} superblock_t;

typedef struct {
    char name[32];
    uint32_t size;
    uint32_t first_block;
    uint32_t flags;
    uint32_t timestamp;
} file_entry_t;

typedef struct {
    file_entry_t entries[MAX_FILES];
    uint32_t count;
} directory_t;

static superblock_t superblock;
static directory_t root_dir;

int victorfs_init(uint32_t device) {
    // Read superblock
    if(!ata_read_sectors(device, 0, 1, (uint8_t*)&superblock)) {
        return 0;
    }
    
    if(superblock.magic != VICTORFS_MAGIC) {
        return 0;
    }
    
    // Read root directory
    if(!ata_read_sectors(device, superblock.root_dir, 
                        sizeof(directory_t) / BLOCK_SIZE + 1,
                        (uint8_t*)&root_dir)) {
        return 0;
    }
    
    return 1;
}

file_t* victorfs_open(const char* name, uint32_t flags) {
    for(uint32_t i = 0; i < root_dir.count; i++) {
        if(strcmp(root_dir.entries[i].name, name) == 0) {
            file_t* file = kmalloc(sizeof(file_t));
            if(!file) return NULL;
            
            file->entry = &root_dir.entries[i];
            file->position = 0;
            file->flags = flags;
            return file;
        }
    }
    
    // File not found, create if requested
    if(flags & FS_CREATE) {
        if(root_dir.count >= MAX_FILES) {
            return NULL;
        }
        
        file_entry_t* entry = &root_dir.entries[root_dir.count++];
        strcpy(entry->name, name);
        entry->size = 0;
        entry->first_block = 0;
        entry->flags = 0;
        entry->timestamp = 0; // TODO: Get real time
        
        // Update directory on disk
        
        file_t* file = kmalloc(sizeof(file_t));
        file->entry = entry;
        file->position = 0;
        file->flags = flags;
        return file;
    }
    
    return NULL;
}

size_t victorfs_read(file_t* file, void* buffer, size_t size) {
    if(!file || !buffer || size == 0) return 0;
    
    size_t to_read = min(size, file->entry->size - file->position);
    if(to_read == 0) return 0;
    
    // Read data blocks
    uint32_t block = file->entry->first_block;
    uint32_t bytes_read = 0;
    
    while(bytes_read < to_read) {
        uint8_t block_data[BLOCK_SIZE];
        if(!ata_read_sectors(0, block, 1, block_data)) {
            break;
        }
        
        size_t copy_size = min(BLOCK_SIZE, to_read - bytes_read);
        memcpy((uint8_t*)buffer + bytes_read, block_data, copy_size);
        bytes_read += copy_size;
        
        // TODO: Follow block chain
        break; // Simplified
    }
    
    file->position += bytes_read;
    return bytes_read;
}