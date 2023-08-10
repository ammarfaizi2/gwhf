
CC ?= cc
CXX ?= c++

# Dependencies
override CFLAGS += -MT "$@" -MMD -MP -MF "$@.d"
override CXXFLAGS += -MT "$@" -MMD -MP -MF "$@.d"

# Flags
override CFLAGS += -fpic -fPIC -Wall -Wextra -O2 -ggdb3 -I. -I./framework/include -Wmissing-prototypes -Wstrict-prototypes
override CXXFLAGS += -fpic -fPIC -Wall -Wextra -O2 -ggdb3 -I. -I./framework/include

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

ifeq ($(OS),Windows_NT)
	SPECFLAGS += -DGWHF_OS_WIN32
	ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
		SPECFLAGS += -DGWHF_ARCH_AMD64
		GWHF_ARCH := amd64
	else
		ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
			SPECFLAGS += -DGWHF_ARCH_AMD64
			GWHF_ARCH := amd64
		endif
		ifeq ($(PROCESSOR_ARCHITECTURE),x86)
			SPECFLAGS += -DGWHF_OS_IA32
			GWHF_ARCH := ia32
		endif
	endif
	GWHF_OS := windows
	LIBGWHF := libgwhf.dll
	TARGET := main.exe
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		SPECFLAGS += -DGWHF_OS_LINUX
		GWHF_OS := linux
	endif
	ifeq ($(UNAME_S),Darwin)
		SPECFLAGS += -DGWHF_OS_OSX
		GWHF_OS := osx
	endif
	UNAME_P := $(shell uname -p)
	ifeq ($(UNAME_P),x86_64)
		SPECFLAGS += -DGWHF_ARCH_AMD64
		GWHF_ARCH := amd64
	endif
	ifneq ($(filter %86,$(UNAME_P)),)
		SPECFLAGS += -DGWHF_ARCH_IA32
		GWHF_ARCH := ia32
	endif
	ifneq ($(filter arm%,$(UNAME_P)),)
		SPECFLAGS += -DGWHF_ARCH_ARM
		GWHF_ARCH := arm
	endif
	SPECFLAGS += -DUSE_POSIX_THREAD -D_GNU_SOURCE
	LIBGWHF := libgwhf.so
	TARGET := main
endif

override CFLAGS += $(SPECFLAGS)
override CXXFLAGS += $(SPECFLAGS)

# Sources
C_SRCS_FRAMEWORK := \
	framework/event/epoll.c \
	framework/os/$(GWHF_OS)/socket.c \
	framework/gwhf.c \
	framework/thread.c

ifeq ($(GWHF_OS),windows)
endif

ifeq ($(GWHF_OS),linux)
	C_SRCS_FRAMEWORK += framework/os/linux/signal.c
endif

C_SRCS_APP := app/main.c

# Objects
OBJS_FRAMEWORK := $(C_SRCS_FRAMEWORK:.c=.o) $(CXX_SRCS_FRAMEWORK:.cc=.o)
OBJS_APP := $(C_SRCS_APP:.c=.o) $(CXX_SRCS_APP:.cc=.o)
DEPS := $(OBJS_FRAMEWORK:.o=.o.d) $(OBJS_APP:.o=.o.d)

all: $(TARGET)

$(TARGET): $(OBJS_APP) $(LIBGWHF)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS) -L. -lgwhf

$(LIBGWHF): $(OBJS_FRAMEWORK)
	$(CXX) $(LDFLAGS) -shared -o $@ $^ $(LDLIBS)

-include $(DEPS)

clean:
	rm -f $(OBJS_FRAMEWORK) $(OBJS_APP) $(DEPS) $(LIBGWHF) $(TARGET)

.PHONY: all clean
