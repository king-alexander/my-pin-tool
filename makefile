
SOURCES=hello.cpp

TARGET32=helloplugin.plx
TARGET64=$(TARGET32)64

# Be careful messing with anything below here!

CXX=g++
LD=g++

# Definitions used by IDA
IDADEFS=-D__IDP__ -D__PLUGIN__ -D__LINUX__ -DNO_OBSOLETE_FUNCS

# Compiler options
COPTS=-m32 -fpic -fvisibility=hidden -fvisibility-inlines-hidden	\
      --shared -fno-diagnostics-show-caret -fdiagnostics-show-option	\
      -fwrapv -fpic -pipe -fno-strict-aliasing -pthread -fno-rtti

WARNINGS=-Wall -Wextra -Wno-sign-compare -Wshadow -Wunused		\
         -Wformat=2 -Werror=format-security -Werror=format-nonliteral	\
         -Wno-missing-field-initializers -Wno-unused-local-typedefs

# Add more include paths here if needed
INCFLAGS=-I$(IDASDK)/include

# Build an initial set of compiler flags
CFLAGS=$(IDADEFS) $(COPTS) $(WARNINGS) $(INCFLAGS)

# Check if this is a production build (i.e., NDEBUG is defined)
ifdef NDEBUG
NDEBUGFLAGS=-O2 -ffunction-sections -fdata-sections -DNDEBUG -fomit-frame-pointer -g -D_FORTIFY_SOURCE=2
CFLAGS+=$(NDEBUGFLAGS)
else
DEBUGFLAGS=-g -D_DEBUG
CFLAGS+=$(DEBUGFLAGS)
endif

# Initial Linker flags
EXTRA_LDFLAGS=-L$(IDA) -lrt -lpthread -lc -Wl,--version-script=./plugin.script

# Since linking through g++, give it the CFLAGS again
LDFLAGS=$(CFLAGS) $(EXTRA_LDFLAGS)


# Stash the object files in different 32 and 64 directories
BUILDDIR32=obj32
BUILDDIR64=obj64

# Build the list of 32 and 64 objects
OBJECTS32=$(SOURCES:%.cpp=$(BUILDDIR32)/%.o)
OBJECTS64=$(SOURCES:%.cpp=$(BUILDDIR64)/%.o)


#####
# Now the build rules. Modify these if you need.
#####

all: $(TARGET32) $(TARGET64)

print-%  : ; @echo $* = $($*)

plugin.script:
	cp $(IDASDK)/plugins/plugin.script .

# 32 build rules
$(BUILDDIR32):
	mkdir -p $(BUILDDIR32)

$(BUILDDIR32)/%.o: %.cpp $(BUILDDIR32)
	$(CXX) $(CFLAGS) -c -o $@ $<

$(TARGET32): plugin.script $(OBJECTS32)
	$(LD) $(LDFLAGS) -lida $(OBJECTS32) -o $(TARGET32)

# 64 build rules
$(BUILDDIR64):
	mkdir -p $(BUILDDIR64)

$(BUILDDIR64)/%.o: %.cpp $(BUILDDIR64)
	$(CXX) -D__EA64__ $(CFLAGS) -c -o $@ $<

$(TARGET64): plugin.script $(OBJECTS64)
	$(LD) -D__EA64__ $(LDFLAGS) -lida64 $(OBJECTS64) -o $(TARGET64)

clean:
	rm -rf plugin.script
	rm -rf $(BUILDDIR32)
	rm -rf $(TARGET32)
	rm -rf $(BUILDDIR64)
	rm -rf $(TARGET64)
