# Victor OS Makefile

CC = gcc
CXX = g++
AS = nasm
LD = ld

CFLAGS = -m32 -ffreestanding -O2 -Wall -Wextra -fno-stack-protector
CXXFLAGS = -m32 -ffreestanding -O2 -Wall -Wextra -fno-exceptions -fno-rtti
ASFLAGS = -f elf32
LDFLAGS = -m elf_i386 -T kernel/linker.ld -nostdlib

KERNEL_SOURCES = \
    kernel/src/kernel.c \
    kernel/src/screen.c \
    kernel/src/memory.c \
    kernel/src/gdt.c \
    kernel/src/idt.c \
    kernel/src/isr.c \
    kernel/src/irq.c \
    kernel/src/timer.c \
    kernel/src/keyboard.c \
    kernel/src/process.c \
    fs/victorfs.c \
    ui/desktop.c \
    apps/shell/shell.c

KERNEL_OBJECTS = $(KERNEL_SOURCES:.c=.o)
BOOT_OBJECTS = boot/boot.o boot/multiboot_header.o

all: victor-os.iso

kernel.bin: $(BOOT_OBJECTS) $(KERNEL_OBJECTS)
    $(LD) $(LDFLAGS) -o $@ $^

%.o: %.c
    $(CC) $(CFLAGS) -c $< -o $@

%.o: %.asm
    $(AS) $(ASFLAGS) $< -o $@

victor-os.iso: kernel.bin
    mkdir -p iso/boot/grub
    cp kernel.bin iso/boot/
    cp grub.cfg iso/boot/grub/
    grub-mkrescue -o victor-os.iso iso

run: victor-os.iso
    qemu-system-x86_64 -cdrom victor-os.iso -m 256M

debug: victor-os.iso
    qemu-system-x86_64 -cdrom victor-os.iso -m 256M -s -S &
    gdb -ex "target remote localhost:1234" -ex "symbol-file kernel.bin"

clean:
    rm -f $(KERNEL_OBJECTS) $(BOOT_OBJECTS) kernel.bin victor-os.iso
    rm -rf iso

.PHONY: all clean run debug