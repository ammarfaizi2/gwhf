
CC ?= clang
CXX ?= clang++

# Dependencies
override CFLAGS += -MT "$@" -MMD -MP -MF "$@.d"
override CXXFLAGS += -MT "$@" -MMD -MP -MF "$@.d"

# Flags
override CFLAGS += -Wall -Wextra -O2 -g -I. -I./framework/include -Wmissing-prototypes -Wstrict-prototypes
override CXXFLAGS += -Wall -Wextra -O2 -g -I. -I./framework/include

# Libraries
override LDLIBS +=
override LDFLAGS += -O2 -g

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

PFLAGS =
ifeq ($(OS),Windows_NT)
	PFLAGS += -D GWHF_OS_WIN32 -D _WIN32 -D WIN32
	ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
		PFLAGS += -D GWHF_ARCH_AMD64
	else
		ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
			PFLAGS += -D GWHF_ARCH_AMD64
		endif
		ifeq ($(PROCESSOR_ARCHITECTURE),x86)
			PFLAGS += -D GWHF_ARCH_IA32
		endif
	endif
	GWHF_OS = windows
	LIBGWHF = libgwhf.dll
	TARGET = main.exe
	override LDLIBS += -lwsock32 -lws2_32
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		PFLAGS += -D GWHF_OS_LINUX
		GWHF_OS = linux
	endif
	ifeq ($(UNAME_S),Darwin)
		PFLAGS += -D GWHF_OS_OSX
		GWHF_OS = osx
	endif
	UNAME_P := $(shell uname -p)
	ifeq ($(UNAME_P),x86_64)
		PFLAGS += -D GWHF_ARCH_AMD64
	endif
	ifneq ($(filter %86,$(UNAME_P)),)
		PFLAGS += -D GWHF_ARCH_IA32
	endif
	ifneq ($(filter arm%,$(UNAME_P)),)
		PFLAGS += -D GWHF_ARCH_ARM
	endif
	LIBGWHF = libgwhf.so
	TARGET = main
	override CFLAGS += -fpic -fPIC
	override CXXFLAGS += -fpic -fPIC
	override LDFLAGS += -fpic -fPIC
	override LDLIBS += -lpthread
endif

override CFLAGS += $(PFLAGS)
override CXXFLAGS += $(PFLAGS)

C_SRCS_FRAMEWORK += \
	framework/gwhf.c

C_SRCS_FRAMEWORK += \
	framework/os/$(GWHF_OS)/socket.c

ifeq ($(GWHF_OS),windows)
C_SRCS_FRAMEWORK += \
	framework/os/windows/wepoll.c
endif

C_SRCS_APP += \
	app/main.c

OBJS_FRAMEWORK := $(C_SRCS_FRAMEWORK:.c=.o) $(CXX_SRCS_FRAMEWORK:.cc=.o)
OBJS_APP := $(C_SRCS_APP:.c=.o) $(CXX_SRCS_APP:.cc=.o)
DEPS := $(OBJS_FRAMEWORK:.o=.o.d) $(OBJS_APP:.o=.o.d)

all: $(TARGET)

$(TARGET): $(OBJS_APP)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(OBJS_FRAMEWORK)

$(LIBGWHF): $(OBJS_FRAMEWORK)
	$(CXX) $(LDFLAGS) -shared -o $@ $^ $(LDLIBS)

-include $(DEPS)

clean:
	rm -f $(OBJS_FRAMEWORK) $(OBJS_APP) $(DEPS) $(LIBGWHF) main

.PHONY: all clean
