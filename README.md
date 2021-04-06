# Simple-CPP-Networking
Simple to use C++ Header-Only Library for TCP Connections

# Dependencies
- C++17
- PThread

# How To
Just include the header (`#include "simple_networking.h"`) and link your program against PThread.

## Linking PThread with G++
```bash
g++ src.c -pthread
```

## Linking PThread with CMake
```cmake
find_package(Threads REQUIRED)

target_link_libraries(MY_TARGET PRIVATE Threads::Threads)
```
(in version 3.1.0+)

# Usage
TODO

# Upcoming Features
- [ ] timeout for clients
- [ ] better handling of shortreads/-writes
