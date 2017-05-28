TARGET = listcap
CXXFLAGS = -std=c++0x -MMD -MP
LDLIBS = -ltins
CC = g++

SRCS := $(wildcard *.cpp)
OBJECTS := $(SRCS:%.cpp=%.o)
DEPS := $(OBJECTS:%.o=%.d)

$(TARGET): $(OBJECTS)

.PHONY: clean
clean:
	$(RM) $(OBJECTS) $(DEPS) $(TARGET)

-include $(DEPS)
