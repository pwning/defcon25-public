CC=gcc
CC_32=i686-w64-mingw32-gcc
CC_64=x86_64-w64-mingw32-gcc
# TODO Change as appropriate
NAME=riscv
SOURCES=$(NAME).c
INCLUDES=$(NAME).h opcodes.h

UNAME=$(shell uname)
ifeq ($(UNAME),Darwin)
	DYLIB=lib$(NAME).dylib
else
	DYLIB=lib$(NAME).so
endif

all: $(NAME)_32.dll $(NAME)_64.dll $(DYLIB) py$(NAME).py

clean:
	rm -f $(NAME)_32.dll $(NAME)_64.dll $(DYLIB) py$(NAME).py py$(NAME).pyc

$(NAME)_32.dll: $(SOURCES) $(INCLUDES)
	$(CC_32) -shared -o $@ $(SOURCES)

$(NAME)_64.dll: $(SOURCES) $(INCLUDES)
	$(CC_64) -shared -o $@ $(SOURCES)

ifeq ($(UNAME),Darwin)
$(DYLIB): $(SOURCES) $(INCLUDES)
	$(CC) -dynamiclib -o $@ $(SOURCES)
else
$(DYLIB): $(SOURCES) $(INCLUDES)
	$(CC) -fPIC -shared -Wl,-soname,$@ -o $@ $(SOURCES)
endif

py$(NAME).py: $(INCLUDES)
	python generate_py.py $(NAME)
