/**
 * @file client.cpp
 * @brief Implementation of socket client creation and connect.
 */

// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the Apache License, Version 2.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://www.apache.org/licenses/LICENSE-2.0>.

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
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

#include <climits>

module ianet;

namespace ianet
{
  auto create_socket_client(Context &ctx, EProtocolType protocol) -> Result<SocketClient>
  {
    (void) ctx;

    auto client = make_box<SocketClient_T>();
    client->protocol = protocol;
    return client;
  }

  auto socket_client_connect(SocketClient &client, const String &address, u16 port) -> Result<Connection>
  {
    const int type = client->protocol == EProtocolType::TCP ? SOCK_STREAM : SOCK_DGRAM;

#if AU_PLATFORM_WINDOWS
    const int proto = client->protocol == EProtocolType::TCP ? IPPROTO_TCP : IPPROTO_UDP;
    const NativeSocket s = socket(AF_INET, type, proto);
    if (s == INVALID_SOCKET)
      return fail("socket failed: {}", WSAGetLastError());
#else
    const NativeSocket s = socket(AF_INET, type, 0);
    if (!native_socket_valid(s))
      return fail("socket failed: {}", errno);
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

#if AU_PLATFORM_WINDOWS
    if (InetPtonA(AF_INET, address.c_str(), &addr.sin_addr) != 1)
#else
    if (inet_pton(AF_INET, address.c_str(), &addr.sin_addr) != 1)
#endif
    {
      native_socket_close(s);
      return fail("invalid IPv4 address string");
    }

#if AU_PLATFORM_WINDOWS
    if (connect(s, reinterpret_cast<sockaddr *>(&addr), static_cast<int>(sizeof(addr))) == SOCKET_ERROR)
#else
    if (::connect(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
#endif
    {
#if AU_PLATFORM_WINDOWS
      const int err = WSAGetLastError();
#else
      const int err = errno;
#endif
      native_socket_close(s);
      return fail("connect failed: {}", err);
    }

    auto conn = __connection_from_socket(s);
    if (conn.is_err())
      native_socket_close(s);
    return conn;
  }

  auto socket_client_connect(SocketClient &client, const String &address, u16 port, u32 timeout_ms)
      -> Result<Connection>
  {
    const int type = client->protocol == EProtocolType::TCP ? SOCK_STREAM : SOCK_DGRAM;

#if AU_PLATFORM_WINDOWS
    const int proto = client->protocol == EProtocolType::TCP ? IPPROTO_TCP : IPPROTO_UDP;
    const NativeSocket s = socket(AF_INET, type, proto);
    if (s == INVALID_SOCKET)
      return fail("socket failed: {}", WSAGetLastError());
#else
    const NativeSocket s = socket(AF_INET, type, 0);
    if (!native_socket_valid(s))
      return fail("socket failed: {}", errno);
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

#if AU_PLATFORM_WINDOWS
    if (InetPtonA(AF_INET, address.c_str(), &addr.sin_addr) != 1)
#else
    if (inet_pton(AF_INET, address.c_str(), &addr.sin_addr) != 1)
#endif
    {
      native_socket_close(s);
      return fail("invalid IPv4 address string");
    }

#if AU_PLATFORM_WINDOWS
    u_long non_blocking = 1;
    if (ioctlsocket(s, FIONBIO, &non_blocking) != 0)
    {
      const int err = WSAGetLastError();
      native_socket_close(s);
      return fail("set non-blocking failed: {}", err);
    }
    if (connect(s, reinterpret_cast<sockaddr *>(&addr), static_cast<int>(sizeof(addr))) == SOCKET_ERROR &&
        WSAGetLastError() != WSAEWOULDBLOCK)
    {
      const int err = WSAGetLastError();
      native_socket_close(s);
      return fail("connect failed: {}", err);
    }
    WSAPOLLFD descriptor{};
    descriptor.fd = s;
    descriptor.events = POLLOUT;
    const int wait_ms = timeout_ms > static_cast<u32>(INT_MAX) ? INT_MAX : static_cast<int>(timeout_ms);
    const int ready = WSAPoll(&descriptor, 1U, wait_ms);
    if (ready == SOCKET_ERROR)
    {
      const int err = WSAGetLastError();
      native_socket_close(s);
      return fail("connect poll failed: {}", err);
    }
    if (ready == 0)
    {
      native_socket_close(s);
      return fail("connect timed out after {} ms", timeout_ms);
    }
    int connect_error = 0;
    int option_length = static_cast<int>(sizeof(connect_error));
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&connect_error), &option_length) != 0 ||
        connect_error != 0)
    {
      native_socket_close(s);
      return fail("connect failed: {}", connect_error);
    }
    non_blocking = 0;
    if (ioctlsocket(s, FIONBIO, &non_blocking) != 0)
    {
      const int err = WSAGetLastError();
      native_socket_close(s);
      return fail("restore blocking mode failed: {}", err);
    }
#else
    const int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0 || fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      const int err = errno;
      native_socket_close(s);
      return fail("set non-blocking failed: {}", err);
    }
    if (::connect(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0 && errno != EINPROGRESS)
    {
      const int err = errno;
      native_socket_close(s);
      return fail("connect failed: {}", err);
    }
    pollfd descriptor{};
    descriptor.fd = s;
    descriptor.events = POLLOUT;
    const int wait_ms = timeout_ms > static_cast<u32>(INT_MAX) ? INT_MAX : static_cast<int>(timeout_ms);
    int ready = 0;
    do
    {
      ready = ::poll(&descriptor, 1U, wait_ms);
    } while (ready < 0 && errno == EINTR);
    if (ready < 0)
    {
      const int err = errno;
      native_socket_close(s);
      return fail("connect poll failed: {}", err);
    }
    if (ready == 0)
    {
      native_socket_close(s);
      return fail("connect timed out after {} ms", timeout_ms);
    }
    int connect_error = 0;
    socklen_t option_length = sizeof(connect_error);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, &connect_error, &option_length) < 0 || connect_error != 0)
    {
      native_socket_close(s);
      return fail("connect failed: {}", connect_error);
    }
    if (fcntl(s, F_SETFL, flags) < 0)
    {
      const int err = errno;
      native_socket_close(s);
      return fail("restore blocking mode failed: {}", err);
    }
#endif

    auto conn = __connection_from_socket(s);
    if (conn.is_err())
      native_socket_close(s);
    return conn;
  }
} // namespace ianet
