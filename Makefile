SRCS = $(shell find -name '*.c')
OBJS = $(SRCS:.c=.o)
EXEC = tr
CFLAGS = -Wall  
LFLAGS =  
CC = gcc
$(EXEC): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LFLAGS)

$(OBJS): $(SRCS)
	$(CC) -c $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(OBJS) $(EXEC)



