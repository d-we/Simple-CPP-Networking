// Copyright [2023] <Daniel Weber>

#ifndef SIMPLE_NETWORKING_H
#define SIMPLE_NETWORKING_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cassert>
#include <climits>
#include <cstddef>
#include <optional>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace simple_networking {

// ==========================================================================
//                            GLOBAL CONFIGURATION
// ==========================================================================
// internal message format: message length (4B Little Endian) | message
static constexpr int kMessageLengthBytes = 4;
static constexpr int kMaximumMessageLength = 300000;

// ==========================================================================
//                            ByteArray 
// ==========================================================================
/// Simple wrapper around std::vector<std::byte> which is used to represent bytearrays
class ByteArray {
 public:
  ByteArray() = default;
  explicit ByteArray(int array_length);
  ByteArray(const char* byte_array_raw, int array_length);
  std::string ToString();
  std::string ToHexEncodedString();
  size_t Size();
  void Reserve(size_t size);
  void Append(std::byte byte);
  void Append(const char byte);
  /// erases elements (both indices are inclusive)
  /// \param first first index to erase
  /// \param last last index to erase
  void Erase(size_t first, size_t last);
  std::byte& operator[](std::size_t idx);
  const std::byte& operator[](std::size_t idx) const;
 private:
  std::vector<std::byte> bytes_;
};

inline ByteArray::ByteArray(int array_length) {
  bytes_ = std::vector<std::byte>(array_length, static_cast<std::byte>(0));
}

inline ByteArray::ByteArray(const char* byte_array_raw, int array_length) {
  bytes_.reserve(array_length);
  for (int i = 0; i < array_length; i++) {
    bytes_.push_back(std::byte{static_cast<unsigned char>(byte_array_raw[i])});
  }
}

inline std::string ByteArray::ToString() {
  std::stringstream res;
  for (const std::byte& b : bytes_) {
    res << static_cast<char>(std::to_integer<int>(b));
  }
  return res.str();
}

inline std::string ByteArray::ToHexEncodedString() {
  std::stringstream res;
  for (const std::byte& b : bytes_) {
    res << "\\x" << std::hex << (std::to_integer<int>(b) & 0xff);
  }
  return res.str();
}

inline size_t ByteArray::Size() {
  return bytes_.size();
}

inline void ByteArray::Reserve(size_t size) {
  bytes_.reserve(size);
}

inline void ByteArray::Append(std::byte byte) {
  bytes_.push_back(byte);
}

inline void ByteArray::Erase(size_t first, size_t last) {
  assert(first < bytes_.size());
  assert(last < bytes_.size());
  bytes_.erase(bytes_.begin() + first, bytes_.begin() + last);
}

inline void ByteArray::Append(const char byte) {
  Append(std::byte{static_cast<unsigned char>(byte)});
}

inline std::byte& ByteArray::operator[](std::size_t idx) {
  return bytes_[idx];
}

inline const std::byte& ByteArray::operator[](std::size_t idx) const {
  return bytes_[idx];
}

// ==========================================================================
//                    Utility Functions for Communication 
// ==========================================================================

inline ByteArray EncodeMessageLength(int message_length) {
  ByteArray result(kMessageLengthBytes);

  for (int i = 0; i < kMessageLengthBytes; i++) {
    result[i] = static_cast<std::byte>(message_length >> (i * 8));
  }
  return result;
}

inline int DecodeMessageLength(ByteArray message_length_bytes) {
  uint32_t decoded_length = 0;
  for (int i = 0; i < kMessageLengthBytes; i++) {
    uint8_t c = static_cast<uint8_t>(message_length_bytes[i]);
    decoded_length += static_cast<uint32_t>(c) << (8 * i);
  }
  return decoded_length;
}

inline int SendNetworkMessage(int client_socket, ByteArray message) {
  if (message.Size() > kMaximumMessageLength) {
    return -1;
  }
  if (client_socket == -1) {
    return -2;
  }

  // send message size
  ByteArray encoded_length = EncodeMessageLength(message.Size());
  for (size_t send_bytes = 0; send_bytes < encoded_length.Size();) {
    int bytes = send(client_socket,
                     encoded_length.ToString().c_str(),
                     encoded_length.Size(),
                     MSG_NOSIGNAL); // ignore SIGPIPE (handled via return value)
    if (bytes < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      return -3;
    }
    send_bytes += bytes;
  }

  // send message content
  std::string message_str = message.ToString();
  for (size_t send_bytes = 0; send_bytes < message.Size();) {
    int bytes = send(client_socket,
                     message_str.c_str() + send_bytes,
                     message.Size() - send_bytes,
                     MSG_NOSIGNAL); // ignore SIGPIPE (handled via return value)
    if (bytes <= 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      return -4;
    }
    send_bytes += bytes;
  }
  return 0;
}

inline int SendNetworkMessage(int client_sock, const std::string& message) {
  return SendNetworkMessage(client_sock, ByteArray(message.c_str(), message.size()));
}



// ==========================================================================
//                                 SERVER
// ==========================================================================
// TODO: implement shutdown logic (also add signal handler for ctrl+c?)
// TODO: implement timeout logic
class TCPServer {
 public:
  TCPServer();
  explicit TCPServer(bool verbose);
  TCPServer(bool verbose, int client_timeout_in_seconds, int backlog_size);
  ~TCPServer();
  void Bind(const std::string& ip_address, size_t port);
  template <typename T> void Listen(void(handler_func)(T arg, int client_socket, ByteArray message),
              T handler_arg, bool blocking);
  void StopListening();
  int ReadNBytesFromSocket(int socket,
                           size_t bytes_to_read,
                           int* errnum,
                           ByteArray* message_buffer);
  int DisconnectFromClient(int client_socket);
 private:
  template <typename T> void Dispatcher(void(handler_function)(T arg, int client_socket, ByteArray message),
                                        T handler_arg);
  template <typename T> void ClientHandlingIntern(int client_socket,
                            void(handler_function)(T arg, int client_socket, ByteArray message),
                            T handler_arg);
  void MakeSocketNonBlocking(int socket);
  ///
  /// \param socket socket to read from
  /// \param bytes_to_read number of bytes to read
  /// \param errnum saved errno in case of error (return value -1)
  /// \param message_buffer bytearray containing read bytes
  /// \return number of bytes read or 0 on client disconnect or -1 on error
  void StoreInReadBuffer(int socket, ByteArray content);
  void ThrowErrorAndAbort(std::string error_message);
  void PrintInfoMessage(const std::string& message);
  void CleanupSocket(int socket);
  void CleanupEverything();

  int server_fd_;
  int epoll_fd_;
  bool verbose_;
  int backlog_size_;
  int client_timeout_in_seconds_;
  std::atomic<bool> shutdown_;
  std::unordered_map<int, ByteArray> read_buffers_;
  std::unordered_set<int> open_sockets_;
  std::optional<std::thread> handler_thread_;
  static constexpr int kEpollQueueSize = 255;
  static constexpr int kEpollWaitTimeout = 5000;
  static constexpr int kDefaultBacklogSize = 500;
  static constexpr int kDefaultClientTimeout = 5;
};

inline TCPServer::TCPServer()
    : server_fd_(-1),
      epoll_fd_(-1),
      verbose_(false),
      backlog_size_(kDefaultBacklogSize),
      client_timeout_in_seconds_(kDefaultClientTimeout),
      shutdown_(false) {}

inline TCPServer::TCPServer(bool verbose)
    : server_fd_(-1),
      epoll_fd_(-1),
      verbose_(verbose),
      backlog_size_(kDefaultBacklogSize),
      client_timeout_in_seconds_(kDefaultClientTimeout),
      shutdown_(false) {}


inline TCPServer::TCPServer(bool verbose,
                            int client_timeout_in_seconds,
                            int backlog_size = kDefaultBacklogSize)
    : server_fd_(-1),
      epoll_fd_(-1),
      verbose_(verbose),
      backlog_size_(backlog_size),
      client_timeout_in_seconds_(client_timeout_in_seconds),
      shutdown_(false) {}

inline TCPServer::~TCPServer() {
  CleanupEverything();
}

inline void TCPServer::CleanupSocket(int socket) {
  open_sockets_.erase(socket);
  read_buffers_.erase(socket);
  // TODO: remove from timeout list
}

inline void TCPServer::CleanupEverything() {
  for (auto it = open_sockets_.begin(); it != open_sockets_.end();) {
    // we iterate like this because CleanupSocket erases the elements
    int socket = *it;
    auto next = ++it;
    close(socket);
    CleanupSocket(socket);
    it = next;
  }
  PrintInfoMessage("Cleanup finished.");
}

inline void TCPServer::Bind(const std::string& ip_address, size_t port) {
  server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd_ == -1) {
    ThrowErrorAndAbort("Failed to create socket!");
  }
  open_sockets_.insert(server_fd_);
  
  // set SO_REUSEADDR to make socket re-bindable
  const int enable = 1;
  int err = setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
  if (err) {
    ThrowErrorAndAbort("Could not set SO_REUSEADDR!");
  }


  struct sockaddr_in server_addr;
  memset(&server_addr, '\0', sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  int succ = inet_aton(ip_address.c_str(), &server_addr.sin_addr);
  if (succ != 1) {
    ThrowErrorAndAbort("Invalid IP-address given (" + ip_address + ")!");
  }
  server_addr.sin_port = htons(port);

  err = bind(server_fd_, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr));
  if (err) {
    ThrowErrorAndAbort("Failed to bind to " + ip_address + ":" + std::to_string(port));
  }
  PrintInfoMessage("Bound to " + ip_address + ":" + std::to_string(port) + ".");
}

template <typename T> inline void TCPServer::Listen(
    void (handler_func)(T arg, int client_socket, ByteArray message),
    T handler_arg,
    bool blocking) {
  // initialize shutdown routine
  shutdown_ = false;

  if (server_fd_ < 0) {
    ThrowErrorAndAbort("Corrupt FD when Listening. Did you forget to call Bind?");
  }
  int err = listen(server_fd_, backlog_size_);
  if (err) {
    ThrowErrorAndAbort("Could not listen on main socket");
  }
  MakeSocketNonBlocking(server_fd_);
  PrintInfoMessage("Started listening.");

  // create epoll fd
  epoll_fd_ = epoll_create(kEpollQueueSize);
  if (epoll_fd_ == -1) {
    ThrowErrorAndAbort("Failed to create Epoll FD.");
  }
  open_sockets_.insert(epoll_fd_);

  // add main socket to epoll set
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;
  ev.data.fd = server_fd_;
  err = epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, server_fd_, &ev);
  if (err) {
    ThrowErrorAndAbort("Adding main socket to Epoll set failed");
  }
  if (blocking) {
    Dispatcher<T>(handler_func, handler_arg);
  } else {
    std::thread handling_thread(&TCPServer::Dispatcher<T>, this, handler_func, handler_arg);
    handler_thread_ = std::move(handling_thread);
  }
}

template <typename T> inline void TCPServer::Dispatcher(
  [[maybe_unused]] void (handler_function)(T arg, int client_socket, ByteArray message),
   T handler_arg) {

  struct epoll_event events[kEpollQueueSize];
  static struct epoll_event ev;
  // events to listen for on client sockets
  ev.events = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;

  while (!shutdown_) {
    // TODO: handle timeouts

    // wait for events on the sockets
    int ready_events_counter = epoll_wait(epoll_fd_, events, 10, kEpollWaitTimeout);
    if (ready_events_counter < 0 && !shutdown_) {
      if (errno == EINTR) {
        // we were killed by an interrupt (e.g. system() or fork())
        continue;
      } else {
        ThrowErrorAndAbort("Unexpected error during epoll_wait");
      }
    }

    // process all events
    for (int i = 0; i < ready_events_counter; i++) {
      // get socket associated with the current event
      int current_socket = events[i].data.fd;

      if (current_socket == server_fd_) {
        PrintInfoMessage("New Client connection");
        // a new client wants to connect
        struct sockaddr_un client_addr;
        socklen_t client_addr_length;
        memset(&client_addr, '\0', sizeof(client_addr));
        memset(&client_addr_length, '\0', sizeof(client_addr_length));

        int client_socket = accept(server_fd_,
                                   reinterpret_cast<struct sockaddr*>(&client_addr),
                                   &client_addr_length);
        if (client_socket < 0) {
          // error upon accepting client connection. hence we just continue with the next event
          continue;
        }
        MakeSocketNonBlocking(client_socket);

        // add client socket to epoll set
        ev.data.fd = client_socket;
        int ret = epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, client_socket, &ev);
        if (ret < 0) {
          close(client_socket);
          continue;
        }
        open_sockets_.insert(client_socket);

        PrintInfoMessage("Accepted new client connection (fd: "
                             + std::to_string(client_socket) + ").");
        // TODO: initialize timeout counters
      } else {  // if (current_socket == server_fd_)
        ClientHandlingIntern<T>(current_socket, handler_function, handler_arg);
      }

    }  // for (int i = 0; i < ready_events_counter; i++)

  }  // while (!shutdown_)
}

inline void TCPServer::StopListening() {
  shutdown_ = true;
  if (handler_thread_.has_value()) {
    handler_thread_->join();
  }
  PrintInfoMessage("Stopped listening.");
}

inline int TCPServer::DisconnectFromClient(int client_socket) {
  // at FIRST remove fd from epoll set (before closing - otherwise delete from epoll set won't
  // work)
  // this is important because child processes can still hold the fd
  epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, client_socket, nullptr);
  int ret = close(client_socket);
  if (ret) {
    // failed to close socket, hence we need to add it back to the epoll set
    static struct epoll_event ev;
    // events to listen for on client sockets
    ev.events = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;
    ev.data.fd = client_socket;
    epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, client_socket, &ev);
    return 1;
  }
  // remove socket from its bookkeeping
  CleanupSocket(client_socket);
  PrintInfoMessage("Closed client connection (fd: "
                       + std::to_string(client_socket) + ").");
  return 0;
}

template <typename T> inline void TCPServer::ClientHandlingIntern(
                                            int client_socket,
                                            void (handler_function)(
                                                T arg,
                                                int client_socket,
                                                ByteArray message),
                                            T handler_arg) {
  int saved_errno = 0;
  ByteArray message_length_bytes;
  int read_bytes = ReadNBytesFromSocket(client_socket,
      kMessageLengthBytes,
      &saved_errno,
      &message_length_bytes);
  if (read_bytes <= 0) {
    if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
      // socket would block hence we just ignore the request
      return;
    }
    // peer closed socket or something else failed - bye bye
    DisconnectFromClient(client_socket);
    return;
  }  // if (read_bytes <= 0)

  // read actual message from the client
  int message_length = DecodeMessageLength(message_length_bytes);
  if (message_length < 0 || message_length > kMaximumMessageLength) {
    ThrowErrorAndAbort("Invalid message length. Something went wrong!");
  }

  saved_errno = 0;
  ByteArray message;
  read_bytes = ReadNBytesFromSocket(client_socket, message_length, &saved_errno, &message);
  if (read_bytes <= 0) {
    if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
      return;
    }
    // peer closed socket or something else failed - bye bye
    DisconnectFromClient(client_socket);
  }

  // call user-provided handler function
  handler_function(handler_arg, client_socket, message);
}

inline void TCPServer::ThrowErrorAndAbort(std::string error_message) {
  // in case we forget proper punctuation
  if (error_message[error_message.size() - 1] != '.' &&
      error_message[error_message.size() - 1] != '?' &&
      error_message[error_message.size() - 1] != '!') {
    error_message.append(".");
  }
  std::cerr << "[-] TCPServer Error: " << error_message << " Aborting!" << std::endl;
  CleanupEverything();
  exit(1);
}

inline void TCPServer::PrintInfoMessage(const std::string& message) {
  if (verbose_) {
    std::cout << "[+] TCPServer: " << message << std::endl;
  }
}


inline void TCPServer::MakeSocketNonBlocking(int socket) {
  int saved_flags = fcntl(socket, F_GETFL);
  if (saved_flags < 0) {
    ThrowErrorAndAbort("Could not retrieve flags for socket.");
  }
  saved_flags |= O_NONBLOCK;
  int ret = fcntl(socket, F_SETFL, saved_flags);
  if (ret < 0) {
    ThrowErrorAndAbort("Could not update flags for socket.");
  }
}

inline void TCPServer::StoreInReadBuffer(int socket, ByteArray content) {
  for (size_t i = 0; i < content.Size(); i++) {
    read_buffers_[socket].Append(content[i]);
  }
}

inline int TCPServer::ReadNBytesFromSocket(int socket,
                                           size_t bytes_to_read,
                                           int* errnum,
                                           ByteArray* message_buffer) {
  assert(errnum != nullptr);
  assert(message_buffer != nullptr);

  size_t overall_bytes_read = 0;
  char* raw_message_buffer = new char[bytes_to_read];

  // check whether there are bytes buffered and if so fetch them
  if (read_buffers_[socket].Size() > 0) {
    int bytes_needed_from_buffer = std::min(read_buffers_[socket].Size(), overall_bytes_read);
    for (int i = 0; i < bytes_needed_from_buffer; i++) {
      raw_message_buffer[i] = static_cast<char>(read_buffers_[socket][i]);
    }
    // remove read bytes from readbuffer
    read_buffers_[socket].Erase(0, bytes_needed_from_buffer - 1);
    overall_bytes_read += bytes_needed_from_buffer;
  }

  // read bytes from the actual socket
  while (overall_bytes_read < bytes_to_read) {
    int current_bytes_read = read(socket,
                                  raw_message_buffer + overall_bytes_read,
                                  bytes_to_read - overall_bytes_read);
    if (current_bytes_read <= 0) {
      if (current_bytes_read == 0) {
        // client wants to close the connection
        delete[] raw_message_buffer;
        return 0;
      }
      *errnum = current_bytes_read == 0 ? 0 : errno;
      if (errno == EAGAIN) {
        // if we cannot read currently; just try again
        continue;
      }
      if (overall_bytes_read > 0) {
        // we already read some parts hence we need to store that to the corresponding readbuffer
        read_buffers_[socket].Reserve(read_buffers_[socket].Size() + overall_bytes_read);
        for (size_t i = 0; i < overall_bytes_read; i++) {
          read_buffers_[socket].Append(raw_message_buffer[i]);
        }
      }
      delete[] raw_message_buffer;
      return -1;
    }
    overall_bytes_read += current_bytes_read;
  }
  *message_buffer = ByteArray(raw_message_buffer, overall_bytes_read);
  delete[] raw_message_buffer;
  return overall_bytes_read;
}

// ==========================================================================
//                                 CLIENT
// ==========================================================================
class TCPClient {
 public:
  TCPClient();
  explicit TCPClient(bool verbose);
  ~TCPClient();
  int Connect(const std::string& ip_address, size_t port);
  void Disconnect();
  int SendMessage(ByteArray message);
  int SendMessage(const std::string& message);
  ByteArray ReadMessage();

 private:
  inline int ReadNBytesFromSocket(
      size_t bytes_to_read,
      int* errnum,
      ByteArray* message_buffer);
  ByteArray EncodeMessageLength(int message_length);
  int client_socket_ = -1;
  ByteArray read_buffer_;
  bool verbose_;
};

inline TCPClient::TCPClient() : verbose_(false) {}

inline TCPClient::TCPClient(bool verbose) : verbose_(verbose) {}

inline TCPClient::~TCPClient() {
  Disconnect();
}

inline int TCPClient::Connect(const std::string& ip_address, size_t port) {
  client_socket_ = socket(AF_INET, SOCK_STREAM, 0);
  if (client_socket_ == -1) {
    return -1;
  }
  struct sockaddr_in server_addr;
  memset(&server_addr, '\0', sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  int succ = inet_aton(ip_address.c_str(), &server_addr.sin_addr);
  if (succ == -1) {
    Disconnect();
    return -2;
  }
  server_addr.sin_port = htons(port);
  int err = connect(client_socket_, reinterpret_cast<struct sockaddr*>(&server_addr),
                    sizeof(server_addr));
  if (err) {
    Disconnect();
    return -3;
  }
  return 0;
}

inline void TCPClient::Disconnect() {
  if (client_socket_ != -1) {
    close(client_socket_);
  }
  client_socket_ = -1;
}

inline int TCPClient::SendMessage(ByteArray message) {
  if (message.Size() > kMaximumMessageLength) {
    return -1;
  }
  if (client_socket_ == -1) {
    return -2;
  }

  // send message size
  ByteArray encoded_length = EncodeMessageLength(message.Size());
  for (size_t send_bytes = 0; send_bytes < encoded_length.Size();) {
    int bytes = send(client_socket_,
                     encoded_length.ToString().c_str(),
                     encoded_length.Size(),
                     MSG_NOSIGNAL); // ignore SIGPIPE (handled via return value)
    if (bytes < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      return -3;
    }
    send_bytes += bytes;
  }

  // send message content
  std::string message_str = message.ToString();
  for (size_t send_bytes = 0; send_bytes < message.Size();) {
    int bytes = send(client_socket_,
                     message_str.c_str() + send_bytes,
                     message.Size() - send_bytes,
                     MSG_NOSIGNAL); // ignore SIGPIPE (handled via return value)
    if (bytes <= 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      return -4;
    }
    send_bytes += bytes;
  }

  return 0;
}

inline int TCPClient::SendMessage(const std::string& message) {
  return SendMessage(ByteArray(message.c_str(), message.size()));
}

// returns error code
inline ByteArray TCPClient::ReadMessage() {
  int saved_errno = 0;
  ByteArray message_length_bytes;
  int read_bytes = ReadNBytesFromSocket(
      kMessageLengthBytes,
      &saved_errno,
      &message_length_bytes);
  if (read_bytes <= 0) {
    if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
      // socket would block hence we just ignore the request
      throw std::runtime_error("Socket would block");
    }
    // peer closed socket or something else failed - bye bye
    throw std::runtime_error("Peer likely closed connection");
  }  // if (read_bytes <= 0)

  // read actual message from the client
  int message_length = DecodeMessageLength(message_length_bytes);
  if (message_length < 0 || message_length > kMaximumMessageLength) {
    // that's fatal at the moment
    throw std::runtime_error("Invalid message length. Something went wrong!");
  }

  saved_errno = 0;
  ByteArray message;
  read_bytes = ReadNBytesFromSocket(message_length, &saved_errno, &message);
  if (read_bytes <= 0) {
    if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
      // TODO: throwing here without saving any state leaves room for error 
      // in case of a partial read after the message length
      throw std::runtime_error("Socket would block");
    }
    // peer closed socket or something else failed - bye bye
    throw std::runtime_error("Peer likely closed connection");
  }
  return message;
}

inline int TCPClient::ReadNBytesFromSocket(size_t bytes_to_read,
                                           int* errnum,
                                           ByteArray* message_buffer) {
  assert(errnum != nullptr);
  assert(message_buffer != nullptr);

  size_t overall_bytes_read = 0;
  char* raw_message_buffer = new char[bytes_to_read];

  // check whether there are bytes buffered and if so fetch them
  if (read_buffer_.Size() > 0) {
    int bytes_needed_from_buffer = std::min(read_buffer_.Size(), overall_bytes_read);
    for (int i = 0; i < bytes_needed_from_buffer; i++) {
      raw_message_buffer[i] = static_cast<char>(read_buffer_[i]);
    }
    // remove read bytes from readbuffer
    read_buffer_.Erase(0, bytes_needed_from_buffer - 1);
    overall_bytes_read += bytes_needed_from_buffer;
  }

  // read bytes from the actual socket
  while (overall_bytes_read < bytes_to_read) {
    int current_bytes_read = read(client_socket_,
                                  raw_message_buffer + overall_bytes_read,
                                  bytes_to_read - overall_bytes_read);
    if (current_bytes_read <= 0) {
      if (current_bytes_read == 0) {
        // client wants to close the connection
        delete[] raw_message_buffer;
        return 0;
      }
      *errnum = current_bytes_read == 0 ? 0 : errno;
      if (errno == EAGAIN) {
        // if we cannot read currently; just try again
        continue;
      }
      if (overall_bytes_read > 0) {
        // we already read some parts hence we need to store that to the corresponding readbuffer
        read_buffer_.Reserve(read_buffer_.Size() + overall_bytes_read);
        for (size_t i = 0; i < overall_bytes_read; i++) {
          read_buffer_.Append(raw_message_buffer[i]);
        }
      }
      delete[] raw_message_buffer;
      return -1;
    }
    overall_bytes_read += current_bytes_read;
  }
  *message_buffer = ByteArray(raw_message_buffer, overall_bytes_read);
  delete[] raw_message_buffer;
  return overall_bytes_read;
}

inline ByteArray TCPClient::EncodeMessageLength(int message_length) {
  ByteArray result(kMessageLengthBytes);

  for (int i = 0; i < kMessageLengthBytes; i++) {
    result[i] = static_cast<std::byte>(message_length >> (i * 8));
  }
  return result;
}

} // namespace networking

#endif /* !SIMPLE_NETWORKING_H */
