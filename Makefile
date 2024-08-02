# Makefile for compiling the trace_syscalls program

CXX = g++
CXXFLAGS = -Wall -std=c++17
LDFLAGS = -lbpf

TARGET = trace_syscalls
SRCS = trace_syscalls.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)