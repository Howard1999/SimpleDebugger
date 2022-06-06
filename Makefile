all: main.cpp sdb.o
	g++ -g -Wall -o hw4 main.cpp sdb.o

%.o: %.cpp
	g++ -c -g -Wall $<

clean:
	rm hw4 *.o