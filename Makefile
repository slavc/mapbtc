CFLAGS += -std=c11 -Wall -Wextra -Werror -pedantic -D_DEFAULT_SOURCE -D_BSD_SOURCE
CFLAGS += -O3 -g3

LDFLAGS += -lcrypto

PROG = mapbtc
SRC = $(shell ls *.c)
OBJ = $(SRC:%.c=%.o)

.PHONY: all clean

all: $(PROG)

clean:
	rm -f *.o $(PROG)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(PROG): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^
