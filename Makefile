CXX=g++
OBJ=loader_demo

.PHONY: all clean

all: $(OBJ)

loader.o: loader.cpp
	$(CXX) -std=c++11 -c loader.cpp

loader_demo: loader.o loader_demo.cpp
	$(CXX) -std=c++11 -o loader_demo loader_demo.cpp loader.o -lbfd

clean:
	rm -f $(OBJ) *.o

