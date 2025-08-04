CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Iinclude
LDFLAGS = -lssl -lcrypto

SRCDIR = src
OBJDIR = obj
BINDIR = .

# Source files
MAIN_SRC = $(SRCDIR)/main.cpp
CLIENT_SRC = $(SRCDIR)/client.cpp
SERVER_SRC = $(SRCDIR)/server.cpp
CA_SETUP_SRC = $(SRCDIR)/ca_setup.cpp

# Object files
MAIN_OBJ = $(OBJDIR)/main.o
CLIENT_OBJ = $(OBJDIR)/client.o
SERVER_OBJ = $(OBJDIR)/server.o
CA_SETUP_OBJ = $(OBJDIR)/ca_setup.o

# Binaries
MAIN_BIN = $(BINDIR)/mini-pki
CLIENT_BIN = $(BINDIR)/mini-pki-client
SERVER_BIN = $(BINDIR)/mini-pki-server

# Targets
all: $(MAIN_BIN) $(CLIENT_BIN) $(SERVER_BIN)

# Compile each object file
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Link the CLI tool
$(MAIN_BIN): $(MAIN_OBJ) $(CA_SETUP_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Link the client executable
$(CLIENT_BIN): $(CLIENT_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Link the server executable
$(SERVER_BIN): $(SERVER_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Clean build artifacts
clean:
	rm -f $(OBJDIR)/*.o $(MAIN_BIN) $(CLIENT_BIN) $(SERVER_BIN)
