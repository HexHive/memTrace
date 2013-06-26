ROOT_DIR = .

SRC_DIR = $(ROOT_DIR)/src
LIB_DIR = $(ROOT_DIR)/lib
INCLUDE_DIR = $(ROOT_DIR)/include


# The compiler
CXX      = g++

# warning options
WARNOPT  = -Wall -Wno-unused-function

# include path
IPATH = -I$(SRC_DIR) -I$(INCLUDE_DIR)

# lib path
LDPATH =

# compiler flags
CXXFLAGS    = ${WARNOPT} ${IPATH} -O0 -g

# Libraries
LIBS      = ${LDPATH}

TARGETS = example libstm_table_gen lmem_table_gen

all: $(TARGETS)

clean:
	rm -f $(TARGETS) *.o $(SRC_DIR)/*.o



%.o:	%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<


lmem_table_gen:	$(SRC_DIR)/table_gen.o $(SRC_DIR)/instr_analyse_helpers.o lmem_table_gen.o
	$(CXX) $(CXXFLAGS) -o $@ $^

example:	$(SRC_DIR)/table_gen.o $(SRC_DIR)/instr_analyse_helpers.o example.o
	$(CXX) $(CXXFLAGS) -o $@ $^

libstm_table_gen:	$(SRC_DIR)/table_gen.o $(SRC_DIR)/instr_analyse_helpers.o libstm_table_gen.o
	$(CXX) $(CXXFLAGS) -o $@ $^

