# Simple-CPP-Networking
Simple to use C++ Header-Only Library for TCP Connections.
The library aims to provide an easy-to-use C++-style wrapper over the Linux socket interface.

## Server Example 
```cpp
void handler([[maybe_unused]] int client_socket, simple_networking::ByteArray message) {
  std::cout << "Received '" << message.ToString() << "'" << std::endl;
}

[...]

simple_networking::TCPServer tcp_server;
tcp_server.Bind("0.0.0.0", 31337);
tcp_server.Listen(&handler, false);

std::cout << "Press key to stop server" << std::endl;
getchar();

tcp_server.StopListening();
```

## Client Example 
```cpp
simple_networking::TCPClient tcp_client;
tcp_client.Connect("127.0.0.1", 31337);
tcp_client.SendMessage("hello server! (1)");
tcp_client.SendMessage("hello server! (2)");
tcp_client.SendMessage("hello server! (3)");
tcp_client.Disconnect();
```


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
The API is not designed to support connections to arbitrary TCP endpoints but instead enables communication between client/server pairs of this library.
One server instance can handle multiple client instances.

## Server API

  Function                      | Description
--------------------------------|---------------------------------------------
`simple_networking:TCPServer()`                   | Constructor creating a TCPServer object.
`simple_networking:TCPServer(bool verbose)`       | Constructor creating a TCPServer object. Allowing to enable verbose mode.
`void TCPServer.Bind(const std::string& ip_address, size_t port)` | Binds server on a given IP and port. 
`void TCPServer.Listen(void (handler_func)(int client_socket, simple_networking::ByteArray message)), bool blocking` | Starts listening. Expects a callback function which is executed upon receiving a message. If  `blocking` is true, a thread will be spawned handling the listener, else the Listen() will never return.
`void TCPServer.StopListening()` | Stops listening.
`int TCPServer.DisconnectFromClient(int client_socket)` | Stops the connection with the client. Returns 0 on success.
`int TCPServer.ReadNBytesFromSocket(int socket, size_t bytes_to_read, int* errnum, simple_networking::ByteArray* message_buffer)` | Reads `bytes_to_read` bytes from a given socket to `message_buffer`. Errors are stored in `errnum`. Returns number of bytes, 0 on client disconnect, or negative numbers on error.


## Client API

  Function                      | Description
--------------------------------|---------------------------------------------
`simple_networking:TCPClient()`                   | Constructor creating a TCPClient object.
`simple_networking:TCPClient(bool verbose)`       | Constructor creating a TCPClient object. Allowing to enable verbose mode.
`int TCPClient.Connect(const std::string& ip_address, size_t port)` | Connects to the given IP and port. Returns 0 on success. 
`void TCPClient.Disconnect()`   | Gracefully terminates the connection to the server.
`int SendMessage(simple_networking::ByteArray message)` |  Sends message to the server. Returns 0 on success.
`int SendMessage(const std::string& message)` | Sends message to the server. Returns 0 on success.


# Future Features
- [ ] timeout for clients
- [ ] more efficient handling of shortreads/-writes
