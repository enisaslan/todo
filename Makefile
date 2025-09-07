# Compiler and flags
CXX = gcc
CXXFLAGS = -I$(DIR) -I$(DIR)/cjson -I$(BOOST_INCLUDE_DIR)
LDFLAGS = -L$(BOOST_LIB_DIR) -lssl -lcrypto -lpthread

# Boost directories (Linux default)
BOOST_INCLUDE_DIR = /usr/include
BOOST_LIB_DIR = /usr/lib/x86_64-linux-gnu

# Source files and target
SRCS = main.c cjson/cJSON.c
OBJS = $(SRCS:.c=.o)
TARGET = server

# Directory
DIR = /home/enis/Desktop/todo

# Build target
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(DIR)/$(TARGET) $(DIR)/$(OBJS)

# Build objects
%.o: %.c
	$(CXX) $(CXXFLAGS) -c $(DIR)/$< -o $(DIR)/$@

# Clean
clean:
	rm -f $(DIR)/*.o $(DIR)/$(TARGET)