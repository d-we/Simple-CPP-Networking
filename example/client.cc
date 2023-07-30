// Copyright [2023] <Daniel Weber>

#include <iostream>
#include <unistd.h>

#include "../simple_networking.h"


int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
  if (argc != 2) {
    std::cout << "USAGE: " << argv[0] << " <port>" << std::endl;
    return 0;
  }
  simple_networking::TCPClient tcp_client(true);
  tcp_client.Connect("127.0.0.1", atoi(argv[1]));
  for (size_t i = 0; i < 10000; i++) {
    std::string msg = "Hello-Server-" + std::to_string(i) ;
    std::cout << "Sending '" << msg << "'" << std::endl;
    int ret = tcp_client.SendMessage(msg);
    assert(ret == 0);
  }
  tcp_client.Disconnect();
  return 0;
}
