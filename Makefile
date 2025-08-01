CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Iinclude

# Source files
SRC_DIR = src
OBJ_DIR = obj

SRCS = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))

# Targets
all: mini-pki mini-pki-server mini-pki-client

mini-pki: $(OBJ_DIR)/main.o $(OBJ_DIR)/ca_setup.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lssl -lcrypto

mini-pki-server: $(OBJ_DIR)/server.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lssl -lcrypto

mini-pki-client: $(OBJ_DIR)/client.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lssl -lcrypto

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) mini-pki mini-pki-server mini-pki-client
