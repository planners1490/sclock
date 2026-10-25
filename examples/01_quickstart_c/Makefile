# scLock C/C++ Makefile Integration Template (macOS arm64)
SCLOCK ?= ../../bin/sclock
TARGET ?= protect_me_locked

.PHONY: all node-locked verify clean

# Default: Portable All-Mac SEP-Attested + 256-Handler MBA Mode (redistributable to all Apple Silicon Macs)
all: $(TARGET)

$(TARGET): protect_me.c
	$(SCLOCK) compile protect_me.c -o $(TARGET) --entry evaluate_protected_gate --seed 0x20261025

# Optional: Single-Machine Physical SEP UID Node-Locked Mode (zero unsealable keys in binary)
node-locked: protect_me.c
	$(SCLOCK) compile protect_me.c -o $(TARGET) --entry evaluate_protected_gate --sep-lock

verify: $(TARGET)
	$(SCLOCK) verify ./$(TARGET)
	./$(TARGET) 20 1234

clean:
	rm -f $(TARGET)
