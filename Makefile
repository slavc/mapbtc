CFLAGS += -std=c11 -Wall -Wextra -Werror -pedantic -D_DEFAULT_SOURCE
CFLAGS += -O3 -g3

PROG = mapbtc
SRC = $(shell ls *.c)
OBJ = $(SRC:%.c=%.o)

.PHONY: all clean

all: $(PROG)

clean:
	rm -f *.o $(PROG)

$(PROG): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^
