CC=gcc
NAME=program
FLAGS=-lz -lpcap

all: $(NAME)

sniffer.o: sniffer.c
	gcc sniffer.c -c

$(NAME): sniffer.o
	gcc sniffer.o -o $(NAME) $(FLAGS)
