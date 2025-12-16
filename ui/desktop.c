#include "desktop.h"

#define SCREEN_WIDTH 1024
#define SCREEN_HEIGHT 768
#define TASKBAR_HEIGHT 30
#define WINDOW_BORDER 2

typedef struct {
    int x, y;
    int width, height;
    char title[32];
    bool active;
    void* buffer;
} window_t;

static window_t windows[10];
static int window_count = 0;
static uint32_t* framebuffer = (uint32_t*)0xFD000000;

void desktop_init() {
    // Initialize VESA/VBE graphics mode
    vbe_init(SCREEN_WIDTH, SCREEN_HEIGHT, 32);
    
    // Clear screen
    desktop_clear(0x003366); // Deep blue background
    
    // Draw taskbar
    desktop_draw_rect(0, SCREEN_HEIGHT - TASKBAR_HEIGHT, 
                     SCREEN_WIDTH, TASKBAR_HEIGHT, 0x222222);
    
    // Draw start button
    desktop_draw_rect(5, SCREEN_HEIGHT - TASKBAR_HEIGHT + 5, 
                     80, 20, 0x444444);
    desktop_draw_text(15, SCREEN_HEIGHT - TASKBAR_HEIGHT + 10, 
                     "Victor OS", 0xFFFFFF);
    
    // Draw clock area
    desktop_draw_rect(SCREEN_WIDTH - 100, SCREEN_HEIGHT - TASKBAR_HEIGHT + 5,
                     95, 20, 0x444444);
}

void desktop_clear(uint32_t color) {
    for(int y = 0; y < SCREEN_HEIGHT; y++) {
        for(int x = 0; x < SCREEN_WIDTH; x++) {
            framebuffer[y * SCREEN_WIDTH + x] = color;
        }
    }
}

void desktop_draw_rect(int x, int y, int w, int h, uint32_t color) {
    for(int dy = 0; dy < h; dy++) {
        for(int dx = 0; dx < w; dx++) {
            int px = x + dx;
            int py = y + dy;
            if(px >= 0 && px < SCREEN_WIDTH && py >= 0 && py < SCREEN_HEIGHT) {
                framebuffer[py * SCREEN_WIDTH + px] = color;
            }
        }
    }
}

void desktop_draw_text(int x, int y, const char* text, uint32_t color) {
    // Simple font rendering (8x8 font)
    extern uint8_t font8x8[256][8];
    
    while(*text) {
        uint8_t c = *text++;
        uint8_t* glyph = font8x8[c];
        
        for(int gy = 0; gy < 8; gy++) {
            for(int gx = 0; gx < 8; gx++) {
                if(glyph[gy] & (1 << gx)) {
                    int px = x + gx;
                    int py = y + gy;
                    if(px < SCREEN_WIDTH && py < SCREEN_HEIGHT) {
                        framebuffer[py * SCREEN_WIDTH + px] = color;
                    }
                }
            }
        }
        x += 8;
    }
}

window_t* desktop_create_window(const char* title, int x, int y, int w, int h) {
    if(window_count >= 10) return NULL;
    
    window_t* win = &windows[window_count++];
    win->x = x;
    win->y = y;
    win->width = w;
    win->height = h;
    strcpy(win->title, title);
    win->active = true;
    
    // Allocate window buffer
    win->buffer = kmalloc(w * h * sizeof(uint32_t));
    
    // Draw window
    desktop_draw_window(win);
    
    return win;
}

void desktop_draw_window(window_t* win) {
    // Draw window border
    desktop_draw_rect(win->x - WINDOW_BORDER, win->y - 25,
                     win->width + 2 * WINDOW_BORDER, 
                     win->height + 25 + WINDOW_BORDER,
                     win->active ? 0x0066CC : 0x666666);
    
    // Draw title bar
    desktop_draw_rect(win->x, win->y - 25, win->width, 25,
                     win->active ? 0x0088FF : 0x888888);
    
    // Draw title
    desktop_draw_text(win->x + 10, win->y - 20, win->title, 0xFFFFFF);
    
    // Draw close button
    desktop_draw_rect(win->x + win->width - 25, win->y - 25, 25, 25, 0xFF4444);
    desktop_draw_text(win->x + win->width - 15, win->y - 20, "X", 0xFFFFFF);
    
    // Draw window content area
    desktop_draw_rect(win->x, win->y, win->width, win->height, 0xFFFFFF);
}