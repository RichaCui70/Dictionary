
##
## This file builds assignment 3
##

##
## Some macros (makefile 'variables') are defined by default
## by make(1).  The ones relevant to C compiling are:
##  CC     : the name of the compiler (defaults to system compiler)
##  CFLAGS : the flags (options) to pass to the compiler
##
## There are similar macros for other languages, for example C++ uses
##  CXX      : the name of the c++ compiler (defaults to system compiler)
##  CXXFLAGS : the flags (options) to pass to the c++ compiler


## explicitly add debugger support to each file compiled,
## and turn on all warnings.  If your compiler is surprised by your
## code, you should be too.
CFLAGS = -g -Wall -Iaalib -I.

## uncomment/change this next line if you need to use a non-default compiler
#CC = cc


##
## We can define variables for values we will use repeatedly below
##

## define the executables we want to build
A3EXE = a3


## define the set of object files we need to build each executable
A3OBJS		= \
			data-reader.o \
			mainline.o

AALIB = libAA.a

AALIBOBJS	= \
			aalib/hash-functions.o \
			aalib/hash-table.o \
			aalib/primes.o

##
## TARGETS: below here we describe the target dependencies and rules
##
all: $(A3EXE)

$(A3EXE): $(A3OBJS) $(AALIB)
	$(CC) $(CFLAGS) -o $(A3EXE) $(A3OBJS) $(AALIB)


## The ar(1) tool is used to create static libraries.  On Linux
## this is still the tool to use, however other platforms are
## moving to the newer libtool(1).  That tool would use a command
## line like the following
##
#	libtool -static -o $(AALIB) $(AALIBOBJS)
$(AALIB): $(AALIBOBJS)
	ar rcs $(AALIB) $(AALIBOBJS)
	

## convenience target to remove the results of a build
clean :
	- rm -f $(A3OBJS) $(A3EXE)
	- rm -f $(AALIBOBJS) $(AALIB)


## tags -- editor support for function definitions
tags : dummy
	ctags *.c aalib/*.c

## a "dummy" dependency forces its parent to run always
dummy :

