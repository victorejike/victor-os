#include "shell.h"

#define MAX_CMD_LENGTH 256
#define HISTORY_SIZE 10

char cmd_buffer[MAX_CMD_LENGTH];
char history[HISTORY_SIZE][MAX_CMD_LENGTH];
int history_index = 0;

void shell_init() {
    vga_puts("Victor OS Shell v0.1\n");
    vga_puts("Type 'help' for available commands\n\n");
}

void shell_run() {
    while(1) {
        vga_puts("victor> ");
        
        // Read command
        int pos = 0;
        while(1) {
            char c = keyboard_getc();
            if(c == '\n') {
                vga_putc('\n');
                cmd_buffer[pos] = 0;
                break;
            } else if(c == '\b') {
                if(pos > 0) {
                    pos--;
                    vga_putc('\b');
                }
            } else if(pos < MAX_CMD_LENGTH - 1) {
                cmd_buffer[pos++] = c;
                vga_putc(c);
            }
        }
        
        // Execute command
        shell_execute(cmd_buffer);
        
        // Save to history
        if(pos > 0) {
            strcpy(history[history_index % HISTORY_SIZE], cmd_buffer);
            history_index++;
        }
    }
}

void shell_execute(const char* cmd) {
    if(strcmp(cmd, "help") == 0) {
        vga_puts("Available commands:\n");
        vga_puts("  help     - Show this help\n");
        vga_puts("  clear    - Clear screen\n");
        vga_puts("  about    - About Victor OS\n");
        vga_puts("  meminfo  - Show memory info\n");
        vga_puts("  ls       - List files\n");
        vga_puts("  cat      - Show file contents\n");
        vga_puts("  ps       - List processes\n");
        vga_puts("  reboot   - Reboot system\n");
        vga_puts("  shutdown - Shutdown system\n");
    } else if(strcmp(cmd, "clear") == 0) {
        vga_clear();
    } else if(strcmp(cmd, "about") == 0) {
        vga_puts("Victor OS v0.1\n");
        vga_puts("A modern, fast operating system\n");
        vga_puts("Built with C and C++\n");
    } else if(strcmp(cmd, "meminfo") == 0) {
        vga_puts("Memory Info:\n");
        vga_puts("  Total blocks: ");
        // TODO: Print actual numbers
        vga_puts("\n  Used blocks: ");
        vga_puts("\n  Free blocks: ");
        vga_puts("\n");
    } else if(strcmp(cmd, "reboot") == 0) {
        vga_puts("Rebooting...\n");
        // Trigger reboot via keyboard controller
        outb(0x64, 0xFE);
    } else if(strcmp(cmd, "shutdown") == 0) {
        vga_puts("Shutting down...\n");
        // QEMU shutdown
        outw(0x604, 0x2000);
    } else if(strlen(cmd) > 0) {
        vga_puts("Unknown command: ");
        vga_puts(cmd);
        vga_puts("\nType 'help' for available commands\n");
    }
}