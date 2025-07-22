# Makefile for PKI Project

CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -Iinclude -Wno-deprecated-declarations
LDFLAGS = -lssl -lcrypto

SRC_DIR = src
BIN_DIR = bin

CLIENT_SRC = $(SRC_DIR)/client.cpp
SERVER_SRC = $(SRC_DIR)/server.cpp
CA_SETUP_SRC = $(SRC_DIR)/ca_setup.cpp
CERTS_SRC = $(SRC_DIR)/keysAndCerts.cpp   # <- Main for generate-certs

CLIENT_BIN = $(BIN_DIR)/pki-client
SERVER_BIN = $(BIN_DIR)/pki-server
CA_SETUP_BIN = $(BIN_DIR)/generate-certs

.PHONY: all clean

all: $(BIN_DIR) $(CLIENT_BIN) $(SERVER_BIN) $(CA_SETUP_BIN)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(CLIENT_BIN): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(SERVER_BIN): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Linking both keysAndCerts.cpp (with main) + ca_setup.cpp (with logic)
$(CA_SETUP_BIN): $(CERTS_SRC) $(CA_SETUP_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf $(BIN_DIR)
