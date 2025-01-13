CXX = g++

CXXFLAGS = -std=c++17 -Wall -Wextra

LIBS = -lpcap -pthread

TARGET = airodump

SRCS = main.cpp airodump.cpp channel_hop.cpp

OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
