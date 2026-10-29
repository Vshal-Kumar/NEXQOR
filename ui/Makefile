# ui/Makefile — GTK4 QRYPTONEX Dashboard Makefile

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -pthread -std=c11 -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L

GTK4_EXISTS := $(shell pkg-config --exists gtk4 && echo yes)

ifeq ($(GTK4_EXISTS),yes)
    GTK_CFLAGS := $(shell pkg-config --cflags gtk4)
    GTK_LIBS   := $(shell pkg-config --libs gtk4)
else
    GTK_CFLAGS :=
    GTK_LIBS   :=
endif

OBJS = main.o ui_app.o ipc_manager.o
TARGET = qhack_ui

.PHONY: all clean check-gtk run

all: check-gtk $(TARGET)

check-gtk:
ifneq ($(GTK4_EXISTS),yes)
	@echo "=========================================================================="
	@echo "Notice: GTK 4 development headers (libgtk-4-dev) not found on host."
	@echo "Please install them via:"
	@echo "  sudo apt update && sudo apt install -y libgtk-4-dev"
	@echo "=========================================================================="
	@exit 1
endif

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(GTK_LIBS)
	@echo "Successfully built: $(TARGET) [GTK 4 Pure C Dashboard]"

%.o: %.c
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -c -o $@ $<

run: all
	./$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
