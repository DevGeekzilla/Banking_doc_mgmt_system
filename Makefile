CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
TARGET = banking_doc_mgmt
SOURCES = main.cpp User.cpp Document.cpp CryptoModule.cpp Audit.cpp menu.cpp
OBJECTS = $(SOURCES:.cpp=.o)
HEADERS = User.h Document.h CryptoModule.h Audit.h menu.h

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS)

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
	rm -f *.exe
