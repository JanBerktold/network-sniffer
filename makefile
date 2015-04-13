CC=gcc
NAME=program
FLAGS=-lz -lpcap
STORAGE=obj

all: $(NAME)

$(STORAGE)/sniffer.o: sniffer.c
	gcc sniffer.c -c
	mv *.o $(STORAGE)/

$(NAME): $(STORAGE)/sniffer.o
	gcc $(STORAGE)/sniffer.o -o $(NAME) $(FLAGS)
