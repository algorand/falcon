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
#            See for some possible configuration macros.
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

OBJ = codec.o common.o deterministic.o falcon.o fft.o fpr.o keygen.o rng.o shake.o sign.o vrfy.o

all: tests/test_deterministic tests/test_falcon tests/speed

clean:
	-rm -f $(OBJ) tests/test_deterministic tests/test_deterministic.o tests/test_falcon tests/test_falcon.o tests/speed tests/speed.o

tests/test_deterministic: tests/test_deterministic.o $(OBJ)
	$(LD) $(LDFLAGS) -o tests/test_deterministic tests/test_deterministic.o $(OBJ) $(LIBS)

tests/test_falcon: tests/test_falcon.o $(OBJ)
	$(LD) $(LDFLAGS) -o tests/test_falcon tests/test_falcon.o $(OBJ) $(LIBS)

tests/speed: tests/speed.o $(OBJ)
	$(LD) $(LDFLAGS) -o tests/speed tests/speed.o $(OBJ) $(LIBS)

codec.o: codec.c inner.h fpr.h
	$(CC) $(CFLAGS) -c -o codec.o codec.c

common.o: common.c inner.h fpr.h
	$(CC) $(CFLAGS) -c -o common.o common.c

deterministic.o: deterministic.c deterministic.h falcon.h
	$(CC) $(CFLAGS) -c -o deterministic.o deterministic.c

falcon.o: falcon.c falcon.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o falcon.o falcon.c

fft.o: fft.c inner.h fpr.h
	$(CC) $(CFLAGS) -c -o fft.o fft.c

fpr.o: fpr.c inner.h fpr.h
	$(CC) $(CFLAGS) -c -o fpr.o fpr.c

keygen.o: keygen.c inner.h fpr.h
	$(CC) $(CFLAGS) -c -o keygen.o keygen.c

rng.o: rng.c inner.h fpr.h
	$(CC) $(CFLAGS) -c -o rng.o rng.c

shake.o: shake.c inner.h fpr.h
	$(CC) $(CFLAGS) -c -o shake.o shake.c

sign.o: sign.c inner.h fpr.h
	$(CC) $(CFLAGS) -c -o sign.o sign.c

tests/speed.o: tests/speed.c falcon.h
	$(CC) $(CFLAGS) -c -o tests/speed.o tests/speed.c

tests/test_falcon.o: tests/test_falcon.c falcon.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o tests/test_falcon.o tests/test_falcon.c

tests/test_deterministic.o: tests/test_deterministic.c deterministic.h falcon.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o tests/test_deterministic.o tests/test_deterministic.c

vrfy.o: vrfy.c inner.h fpr.h
	$(CC) $(CFLAGS) -c -o vrfy.o vrfy.c
