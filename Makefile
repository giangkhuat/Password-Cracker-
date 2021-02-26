CC := clang
CFLAGS := -g -Wall -Werror -fsanitize=address

# Special flags to find libssl-dev includes
CFLAGS += -I/home/curtsinger/.local/include
LDFLAGS := -L/home/curtsinger/.local/lib

all: password-cracker

clean:
	rm -f password-cracker

password-cracker: password-cracker.c
	$(CC) $(CFLAGS) -o password-cracker password-cracker.c $(LDFLAGS) -lcrypto -lpthread -lm
