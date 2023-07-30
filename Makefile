
CC ?= cc
CXX ?= c++

# Dependencies
override CFLAGS += -MT "$@" -MMD -MP -MF "$@.d"
override CXXFLAGS += -MT "$@" -MMD -MP -MF "$@.d"

# Flags
override CFLAGS += -Wall -Wextra -O2 -ggdb3 -I./framework/include -fvisibility=hidden -Wmissing-prototypes -Wstrict-prototypes -ffunction-sections
override CXXFLAGS += -Wall -Wextra -O2 -ggdb3 -I./framework/include -fvisibility=hidden -Wmissing-prototypes -Wstrict-prototypes -ffunction-sections

# Libraries
override LDLIBS += -lpthread
override LDFLAGS += -O2 -ggdb3

# Files
C_SRCS_FRAMEWORK := \
	framework/ev/epoll.c \
	framework/http/request.c \
	framework/http/response.c \
	framework/gwhf.c \
	framework/helpers.c \
	framework/router.c \
	framework/stack16.c

CXX_SRCS_FRAMEWORK :=

C_SRCS_APP := \
	app/main.c

CXX_SRCS_APP :=

OBJS_FRAMEWORK := $(C_SRCS_FRAMEWORK:.c=.o) $(CXX_SRCS_FRAMEWORK:.cpp=.o)
OBJS_APP := $(C_SRCS_APP:.c=.o) $(CXX_SRCS_APP:.cpp=.o)
DEPS := $(OBJS_FRAMEWORK:.o=.o.d) $(OBJS_APP:.o=.o.d)

all: main

main: libgwhf.so $(OBJS_APP)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS) -L. -lgwhf

libgwhf.so: $(OBJS_FRAMEWORK)
	$(CXX) $(LDFLAGS) -shared -o $@ $^ $(LDLIBS)

clean:
	rm -f $(OBJS_FRAMEWORK) $(OBJS_APP) $(DEPS) libgwhf.so main

.PHONY: all clean
