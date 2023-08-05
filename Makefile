
CC ?= cc
CXX ?= c++

# Dependencies
override CFLAGS += -MT "$@" -MMD -MP -MF "$@.d"
override CXXFLAGS += -MT "$@" -MMD -MP -MF "$@.d"

# Flags
override CFLAGS += -fpic -fPIC -Wall -Wextra -O2 -ggdb3 -I./framework/include -Wmissing-prototypes -Wstrict-prototypes
override CXXFLAGS += -fpic -fPIC -Wall -Wextra -O2 -ggdb3 -I./framework/include -Wmissing-prototypes -Wstrict-prototypes

# Libraries
override LDLIBS += -lpthread
override LDFLAGS += -fpic -fPIC -O2 -ggdb3

SANITIZE ?= 0
LTO ?= 0

ifeq ($(SANITIZE),1)
override CFLAGS += -fsanitize=address
override CXXFLAGS += -fsanitize=address
override LDLIBS += -fsanitize=address
endif

ifeq ($(LTO),1)
override CFLAGS += -flto -fvisibility=hidden -ffunction-sections -fdata-sections
override CXXFLAGS += -flto -fvisibility=hidden -ffunction-sections -fdata-sections
override LDFLAGS += -flto -Wl,--gc-sections
endif

# Files
C_SRCS_FRAMEWORK := \
	framework/ev/epoll.c \
	framework/http/request.c \
	framework/http/response.c \
	framework/http/stream.c \
	framework/client.c \
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
