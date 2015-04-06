CC		= gcc
CFLAGS		= -Wall -ansi -c -O3
INCLUDES	= -I./include
LD		= gcc
LDFLAGS		=
LIBS		=

SRCS	= $(wildcard src/*.c)
OBJS	= $(patsubst %.c,%.o,$(SRCS))
EXECS	= ta des_ta
BINDIR	= /datas/teaching/courses/HWSec/labs/bin

.PHONY: help all clean ultraclean

help:
	@echo "Type:"
	@echo "<make> or <make help> to get this help message"
	@echo "<make all> to generate the 'ta' and 'des_ta' executable"
	@echo "<make clean> to clean a bit"
	@echo "<make ultraclean> to really clean"

all: $(EXECS)

ta: ta.o p.o $(OBJS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LIBS) -lm

des_ta: des_ta.o p.o $(OBJS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LIBS) -lm

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

clean:
	rm -f $(OBJS) des_ta.o p.o ta.o

ultraclean:
	rm -f $(OBJS) $(EXECS) des_ta.o ta.o ta.o
