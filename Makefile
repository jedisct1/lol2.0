CC      = clang
CFLAGS  = -std=c11 -O3 -Wall -Wextra -Iinclude
BUILD   = build

.PHONY: all test bench sanitize clean

all: $(BUILD)/test_lol2 $(BUILD)/test_lol2_portable $(BUILD)/test_mini_control $(BUILD)/bench

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/test_lol2: test/test_lol2.c test/vectors.h src/*.c src/*.h include/lol2.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ test/test_lol2.c

$(BUILD)/test_lol2_portable: test/test_lol2.c test/vectors.h src/*.c src/*.h include/lol2.h | $(BUILD)
	$(CC) $(CFLAGS) -DLOL2_FORCE_PORTABLE -o $@ test/test_lol2.c

$(BUILD)/bench: bench/bench.c src/lol2_double.c src/*.h include/lol2.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ bench/bench.c src/lol2_double.c

$(BUILD)/test_mini_control: test/test_mini_control.c src/*.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ test/test_mini_control.c

test: $(BUILD)/test_lol2 $(BUILD)/test_lol2_portable $(BUILD)/test_mini_control
	$(BUILD)/test_lol2
	$(BUILD)/test_lol2_portable
	$(BUILD)/test_mini_control

SAN = -fsanitize=address,undefined

$(BUILD)/test_asan: test/test_lol2.c test/vectors.h src/*.c src/*.h include/lol2.h | $(BUILD)
	$(CC) $(CFLAGS) $(SAN) -o $@ test/test_lol2.c

$(BUILD)/test_asan_portable: test/test_lol2.c test/vectors.h src/*.c src/*.h include/lol2.h | $(BUILD)
	$(CC) $(CFLAGS) $(SAN) -DLOL2_FORCE_PORTABLE -o $@ test/test_lol2.c

$(BUILD)/test_asan_mini: test/test_mini_control.c src/*.h | $(BUILD)
	$(CC) $(CFLAGS) $(SAN) -o $@ test/test_mini_control.c

sanitize: $(BUILD)/test_asan $(BUILD)/test_asan_portable $(BUILD)/test_asan_mini
	$(BUILD)/test_asan
	$(BUILD)/test_asan_portable
	$(BUILD)/test_asan_mini

bench: $(BUILD)/bench
	$(BUILD)/bench

clean:
	rm -rf $(BUILD)
