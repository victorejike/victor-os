#include "kernel.h"
#include "screen.h"
#include "gdt.h"
#include "idt.h"
#include "isr.h"
#include "irq.h"
#include "timer.h"
#include "keyboard.h"
#include "memory.h"

multiboot_info_t* mb_info;

void kernel_main(uint32_t magic, multiboot_info_t* mbi) {
    mb_info = mbi;
    
    // Initialize screen
    vga_clear();
    vga_set_color(0x0F); // White on black
    
    // Print banner
    vga_puts("\n\n");
    vga_puts("   __     __            __                \n");
    vga_puts("   \\ \\   / /__ _ __ ___/ _\\ ___ _ ____   \n");
    vga_puts("    \\ \\ / / _ \\ '__/ _ \\ \\ / _ \\ '__\\ \\ / /\n");
    vga_puts("     \\ V /  __/ | |  __/\\ \\  __/ |   \\ V / \n");
    vga_puts("      \\_/ \\___|_|  \\___\\__/\\___|_|    \\_/  \n");
    vga_puts("              Victor OS v0.1\n");
    vga_puts("==========================================\n\n");
    
    vga_puts("[+] Initializing GDT...\n");
    gdt_init();
    
    vga_puts("[+] Initializing IDT...\n");
    idt_init();
    
    vga_puts("[+] Initializing ISRs...\n");
    isr_init();
    
    vga_puts("[+] Initializing IRQs...\n");
    irq_init();
    
    vga_puts("[+] Initializing memory management...\n");
    memory_init();
    
    vga_puts("[+] Initializing timer...\n");
    timer_init(100); // 100Hz
    
    vga_puts("[+] Initializing keyboard...\n");
    keyboard_init();
    
    vga_puts("[+] Kernel initialized successfully!\n\n");
    vga_puts("Welcome to Victor OS!\n");
    vga_puts("Type 'help' for available commands\n\n");
    vga_puts("victor> ");
    
    // Enable interrupts
    asm volatile("sti");
    
    // Main loop
    while(1) {
        char c = keyboard_getc();
        if(c != 0) {
            vga_putc(c);
        }
    }
}

void panic(const char* message) {
    vga_set_color(0x4F); // Red background
    vga_puts("\n\nKERNEL PANIC: ");
    vga_puts(message);
    vga_puts("\nSystem halted.\n");
    
    // Disable interrupts
    asm volatile("cli");
    
    // Halt
    while(1) {
        asm volatile("hlt");
    }
}