// Copyright [2023] <Daniel Weber>

#include <iostream>
#include "../simple_networking.h"

void handler(int client_socket, simple_networking::ByteArray message) {
  (void) client_socket;
  std::cout << "received message: " << message.ToString() << std::endl;
}

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
  if (argc != 2) {
    std::cout << "USAGE: " << argv[0] << " <port>" << std::endl;
    return 0;
  }
  simple_networking::TCPServer tcp_server;
  tcp_server.Bind("0.0.0.0", atoi(argv[1]));
  tcp_server.Listen(&handler, false);

  std::cout << "Press key to stop server" << std::endl;
  getchar();
  std::cout << "Stopping server" << std::endl;
  tcp_server.StopListening();
  return 0;
}
