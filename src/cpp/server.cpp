/**
 * @file server.cpp
 * @brief Implementation of socket server bind/listen and accept.
 */

// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the PolyForm Noncommercial License 1.0.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://polyformproject.org/licenses/noncommercial/1.0.0>.

module;

#include <auxid/macros.hpp>

#if AU_PLATFORM_WINDOWS
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <cerrno>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

module ianet;

namespace ianet
{
  auto create_socket_server(Context &ctx, EProtocolType protocol, u16 port) -> Result<SocketServer>
  {
    (void) ctx;

    const int type = protocol == EProtocolType::TCP ? SOCK_STREAM : SOCK_DGRAM;

#if AU_PLATFORM_WINDOWS
    const int proto = protocol == EProtocolType::TCP ? IPPROTO_TCP : IPPROTO_UDP;
    const NativeSocket listen_sock = socket(AF_INET, type, proto);
    if (listen_sock == INVALID_SOCKET)
      return fail("socket failed: {}", WSAGetLastError());
#else
    const NativeSocket listen_sock = socket(AF_INET, type, 0);
    if (!native_socket_valid(listen_sock))
      return fail("socket failed: {}", errno);
#endif

    int opt = 1;
#if AU_PLATFORM_WINDOWS
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&opt), sizeof(opt)) ==
        SOCKET_ERROR)
#else
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
#endif
    {
#if AU_PLATFORM_WINDOWS
      const int err = WSAGetLastError();
#else
      const int err = errno;
#endif
      native_socket_close(listen_sock);
      return fail("setsockopt SO_REUSEADDR failed: {}", err);
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

#if AU_PLATFORM_WINDOWS
    if (bind(listen_sock, reinterpret_cast<sockaddr *>(&addr), static_cast<int>(sizeof(addr))) == SOCKET_ERROR)
#else
    if (::bind(listen_sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
#endif
    {
#if AU_PLATFORM_WINDOWS
      const int err = WSAGetLastError();
#else
      const int err = errno;
#endif
      native_socket_close(listen_sock);
      return fail("bind failed: {}", err);
    }

    if (protocol == EProtocolType::TCP)
    {
#if AU_PLATFORM_WINDOWS
      if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR)
#else
      if (::listen(listen_sock, SOMAXCONN) < 0)
#endif
      {
#if AU_PLATFORM_WINDOWS
        const int err = WSAGetLastError();
#else
        const int err = errno;
#endif
        native_socket_close(listen_sock);
        return fail("listen failed: {}", err);
      }
    }

    auto server = make_box<SocketServer_T>();
    server->sock.store(listen_sock);
    server->protocol = protocol;
    server->port = port;
    return server;
  }

  auto socket_server_accept(SocketServer &server) -> Result<Connection>
  {
    if (server->protocol == EProtocolType::UDP)
      return fail("accept is not supported for UDP servers");

#if AU_PLATFORM_WINDOWS
    const auto listen_socket = server->sock.load();
    if (!native_socket_valid(listen_socket))
      return fail("accept failed: server is closed");
    const NativeSocket client_sock = accept(listen_socket, nullptr, nullptr);
    if (client_sock == INVALID_SOCKET)
      return fail("accept failed: {}", WSAGetLastError());
#else
    const auto listen_socket = server->sock.load();
    if (!native_socket_valid(listen_socket))
      return fail("accept failed: server is closed");
    const NativeSocket client_sock = ::accept(listen_socket, nullptr, nullptr);
    if (!native_socket_valid(client_sock))
      return fail("accept failed: {}", errno);
#endif

    auto conn = __connection_from_socket(client_sock);
    if (conn.is_err())
      native_socket_close(client_sock);
    return conn;
  }

  auto socket_server_close(SocketServer &server) -> Result<void>
  {
    if (!server)
      return fail("socket server is not initialized");
    const auto socket = server->sock.exchange(INVALID_NATIVE_SOCKET);
    if (!native_socket_valid(socket))
      return {};
#if AU_PLATFORM_WINDOWS
    (void) shutdown(socket, SD_BOTH);
#else
    (void) ::shutdown(socket, SHUT_RDWR);
#endif
    native_socket_close(socket);
    return {};
  }
} // namespace ianet
