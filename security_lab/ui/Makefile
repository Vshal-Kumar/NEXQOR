# security_lab/ui/Makefile — GTK 4 Security & Attack Lab UI

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -pthread -std=c11 -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE

GTK4_EXISTS := $(shell pkg-config --exists gtk4 && echo yes)

ifeq ($(GTK4_EXISTS),yes)
    GTK_CFLAGS := $(shell pkg-config --cflags gtk4)
    GTK_LIBS   := $(shell pkg-config --libs gtk4)
else
    $(error "GTK 4 development libraries (libgtk-4-dev) not found on host!")
endif

OBJS = main.o attack_ui.o
TARGET = attack_ui

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(GTK_LIBS) -pthread -lm
	@echo "Successfully built: $(TARGET) [GTK 4 Pure-C Security Testing UI]"

%.o: %.c attack_ui.h
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -c -o $@ $<

run: all
	./$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
