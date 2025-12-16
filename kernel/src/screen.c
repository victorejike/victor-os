#include "screen.h"

static uint16_t* video_memory = (uint16_t*)0xB8000;
static int cursor_x = 0;
static int cursor_y = 0;

static void update_cursor() {
    uint16_t pos = cursor_y * VGA_WIDTH + cursor_x;
    
    outb(0x3D4, 0x0F);
    outb(0x3D5, (uint8_t)(pos & 0xFF));
    outb(0x3D4, 0x0E);
    outb(0x3D5, (uint8_t)((pos >> 8) & 0xFF));
}

static void scroll() {
    if(cursor_y >= VGA_HEIGHT) {
        // Move all lines up
        for(int y = 0; y < VGA_HEIGHT - 1; y++) {
            for(int x = 0; x < VGA_WIDTH; x++) {
                video_memory[y * VGA_WIDTH + x] = video_memory[(y + 1) * VGA_WIDTH + x];
            }
        }
        
        // Clear last line
        for(int x = 0; x < VGA_WIDTH; x++) {
            video_memory[(VGA_HEIGHT - 1) * VGA_WIDTH + x] = ' ' | (0x0F << 8);
        }
        
        cursor_y = VGA_HEIGHT - 1;
    }
}

void vga_clear() {
    for(int y = 0; y < VGA_HEIGHT; y++) {
        for(int x = 0; x < VGA_WIDTH; x++) {
            video_memory[y * VGA_WIDTH + x] = ' ' | (0x0F << 8);
        }
    }
    cursor_x = 0;
    cursor_y = 0;
    update_cursor();
}

void vga_putc(char c) {
    if(c == '\n') {
        cursor_x = 0;
        cursor_y++;
    } else if(c == '\r') {
        cursor_x = 0;
    } else if(c == '\b') {
        if(cursor_x > 0) {
            cursor_x--;
            video_memory[cursor_y * VGA_WIDTH + cursor_x] = ' ' | (0x0F << 8);
        }
    } else {
        video_memory[cursor_y * VGA_WIDTH + cursor_x] = c | (0x0F << 8);
        cursor_x++;
    }
    
    if(cursor_x >= VGA_WIDTH) {
        cursor_x = 0;
        cursor_y++;
    }
    
    scroll();
    update_cursor();
}

void vga_puts(const char* str) {
    while(*str) {
        vga_putc(*str);
        str++;
    }
}

void vga_set_color(uint8_t color) {
    // Implementation for color support
}

void vga_set_cursor(int x, int y) {
    cursor_x = x;
    cursor_y = y;
    update_cursor();
}

// Output byte to port
void outb(uint16_t port, uint8_t value) {
    asm volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

// Input byte from port
uint8_t inb(uint16_t port) {
    uint8_t ret;
    asm volatile ("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}