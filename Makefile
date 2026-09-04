# Build script for the Falcon implementation.
#
# ==========================(LICENSE BEGIN)============================
#
# Copyright (c) 2017-2019  Falcon Project
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# ===========================(LICENSE END)=============================
#
# @author   Thomas Pornin <thomas.pornin@nccgroup.com>

.POSIX:

# =====================================================================
#
# Configurable options:
#   CC       C compiler; GCC or Clang are fine; MSVC (2015+) works too.
#   CFLAGS   Compilation flags:
#             * Optimization level -O2 or higher is recommended
#            See config.h for some possible configuration macros.
#   LD       Linker; normally the same command as the compiler.
#   LDFLAGS  Linker options, not counting the extra libs.
#   LIBS     Extra libraries for linking:
#             * If using the native FPU, test_falcon and application
#               code that calls this library may need: -lm
#               (normally not needed on x86, both 32-bit and 64-bit)

CC = clang
CFLAGS = -Wall -Wextra -Wshadow -Wundef -O3 #-pg -fno-pie
LD = clang
LDFLAGS = #-pg -no-pie
LIBS = #-lm

# =====================================================================

OBJ = codec.o common.o falcon.o fft.o fpr.o keygen.o rng.o shake.o sign.o vrfy.o

all: tests/test_deterministic1024 tests/test_deterministic512 tests/test_falcon tests/speed

clean:
	-rm -f $(OBJ) deterministic1024.o deterministic512.o tests/test_deterministic1024 tests/test_deterministic1024.o tests/test_deterministic512 tests/test_deterministic512.o tests/test_falcon tests/test_falcon.o tests/speed tests/speed.o

# The deterministic<n>.c sources are generated from the single template
# deterministic.c.tmpl and committed to the repository, so a normal build just
# compiles them. Each has a rule below that regenerates it first if the
# template has been edited; "make gen" regenerates them unconditionally. Run
# "make gen" after editing scripts/gen_deterministic.sh too: the script is
# deliberately not a prerequisite of the committed sources, since on a fresh
# clone git may check it out with a newer timestamp than them and a plain
# "make" must never rewrite committed sources. "make check-gen" verifies the
# committed sources are in sync with the template (useful in CI).
.PHONY: gen check-gen
gen: deterministic.c.tmpl scripts/gen_deterministic.sh
	sh scripts/gen_deterministic.sh "$(CC)" . 1024 512

check-gen: deterministic.c.tmpl scripts/gen_deterministic.sh
	@tmp=`mktemp -d`; \
	sh scripts/gen_deterministic.sh "$(CC)" "$$tmp" 1024 512; \
	rc=0; \
	cmp -s "$$tmp/deterministic1024.c" deterministic1024.c || { echo "ERROR: deterministic1024.c is out of sync with deterministic.c.tmpl"; rc=1; }; \
	cmp -s "$$tmp/deterministic512.c" deterministic512.c || { echo "ERROR: deterministic512.c is out of sync with deterministic.c.tmpl"; rc=1; }; \
	rm -rf "$$tmp"; \
	if [ $$rc -eq 0 ]; then echo "OK: deterministic1024.c and deterministic512.c are in sync with deterministic.c.tmpl"; else echo "Run 'make gen' to regenerate."; fi; \
	exit $$rc

deterministic1024.c: deterministic.c.tmpl
	sh scripts/gen_deterministic.sh "$(CC)" . 1024

deterministic512.c: deterministic.c.tmpl
	sh scripts/gen_deterministic.sh "$(CC)" . 512

tests/test_deterministic1024: tests/test_deterministic1024.o $(OBJ) deterministic1024.o
	$(LD) $(LDFLAGS) -o tests/test_deterministic1024 tests/test_deterministic1024.o $(OBJ) deterministic1024.o $(LIBS)

tests/test_deterministic512: tests/test_deterministic512.o $(OBJ) deterministic512.o
	$(LD) $(LDFLAGS) -o tests/test_deterministic512 tests/test_deterministic512.o $(OBJ) deterministic512.o $(LIBS)

tests/test_falcon: tests/test_falcon.o $(OBJ)
	$(LD) $(LDFLAGS) -o tests/test_falcon tests/test_falcon.o $(OBJ) $(LIBS)

tests/speed: tests/speed.o $(OBJ)
	$(LD) $(LDFLAGS) -o tests/speed tests/speed.o $(OBJ) $(LIBS)

codec.o: codec.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o codec.o codec.c

common.o: common.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o common.o common.c

deterministic1024.o: deterministic1024.c deterministic.h falcon.h config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o deterministic1024.o deterministic1024.c

deterministic512.o: deterministic512.c deterministic.h falcon.h config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o deterministic512.o deterministic512.c

falcon.o: falcon.c falcon.h config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o falcon.o falcon.c

fft.o: fft.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o fft.o fft.c

fpr.o: fpr.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o fpr.o fpr.c

keygen.o: keygen.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o keygen.o keygen.c

rng.o: rng.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o rng.o rng.c

shake.o: shake.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o shake.o shake.c

sign.o: sign.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o sign.o sign.c

tests/speed.o: tests/speed.c falcon.h
	$(CC) $(CFLAGS) -c -o tests/speed.o tests/speed.c

tests/test_falcon.o: tests/test_falcon.c falcon.h config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o tests/test_falcon.o tests/test_falcon.c

tests/test_deterministic1024.o: tests/test_deterministic1024.c tests/test_deterministic1024_kat.h deterministic.h falcon.h config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o tests/test_deterministic1024.o tests/test_deterministic1024.c

tests/test_deterministic512.o: tests/test_deterministic512.c tests/test_deterministic512_kat.h deterministic.h falcon.h config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o tests/test_deterministic512.o tests/test_deterministic512.c

vrfy.o: vrfy.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o vrfy.o vrfy.c
