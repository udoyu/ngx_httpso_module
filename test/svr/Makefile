INC_PATH    =  -I./ -I../../common
ADD_SRC_PATH = ../../common

LIB_PATH    = 

SHELL = /bin/sh
CC    = gcc
CPP = g++
CFLAGS       = -fPIC -Wall
CPPFLAGS       = -g -O0 -fPIC -Wall -std=c++11 $(INC_PATH)
DEBUGFLAGS   = -g -O0 -D_DEBUG -DDEBUG
RELEASEFLAGS = -O2 -DNDEBUG
LDFLAGS      = -shared
USE_FLAGS = $(RELEASEFLAGS)
ifeq ($(DEBUG), y)
  CFLAGS := $(CFLAGS) $(DEBUGFLAGS)
else
  CFLAGS := $(CFLAGS) $(RELEASEFLAGS)
endif



LIBS        += $(LIB_PATH) 

TARGET  = pp.so
SOURCES = $(shell echo *.cpp $(ADD_SRC_PATH)/*.cpp)
HEADERS = $(shell echo *.h)
OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CPP) $(FLAGS) $(CPPFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS) $(LIBS)

clean:
	rm -f *.o *.so $(ADD_SRC_PATH)/*.o
