#ifndef KERNEL_H
#define KERNEL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define VGA_WIDTH 80
#define VGA_HEIGHT 25
#define NULL 0

typedef struct {
    uint32_t magic;
    uint32_t flags;
    uint32_t checksum;
    uint32_t header_addr;
    uint32_t load_addr;
    uint32_t load_end_addr;
    uint32_t bss_end_addr;
    uint32_t entry_addr;
} multiboot_info_t;

// Memory
void* kmalloc(size_t size);
void kfree(void* ptr);
void memory_init();

// VGA Driver
void vga_clear();
void vga_putc(char c);
void vga_puts(const char* str);
void vga_set_color(uint8_t color);
void vga_set_cursor(int x, int y);

// GDT
void gdt_init();

// IDT
void idt_init();

// ISR
void isr_init();

// IRQ
void irq_init();

// Timer
void timer_init(uint32_t frequency);
uint64_t timer_get_ticks();

// Keyboard
void keyboard_init();
char keyboard_getc();

// String functions
size_t strlen(const char* str);
void strcpy(char* dest, const char* src);
int strcmp(const char* s1, const char* s2);

// Math
int abs(int n);
int max(int a, int b);
int min(int a, int b);

// Kernel panic
void panic(const char* message);

#endif