CC = gcc
CFLAGS = -Wall -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
LDFLAGS = -lcrypto 
OS := $(shell uname -s)
ifeq ($(OS),Darwin)
  CFLAGS += -I/opt/homebrew/opt/openssl/include
  LDFLAGS += -L/opt/homebrew/opt/openssl/lib -framework Security
else ifeq ($(OS),Linux)
else
  $(error, unsupported OS: $(OS))
endif

DF=
LF=
ifeq ($(DEBUG),1)
  DF := -DDEBUG=1
  CFLAGS += -g
else
  CFLAGS += -O3
endif
ifeq ($(ENABLE_LOG),1)
  LF := -DENABLE_LOG=1
endif

all: tun

tun: tun.c
	$(CC) $(DF) $(LF) $(CFLAGS) -o tun tun.c $(LDFLAGS)
	
clean:
	rm -f tun

.phony: clean all
