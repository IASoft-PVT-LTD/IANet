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
  namespace
  {
    auto send_all(NativeSocket s, Span<const u8> data) -> Result<void>
    {
      usize off = 0;
      while (off < data.size())
      {
        const usize remain = data.size() - off;
#if AU_PLATFORM_WINDOWS
        const int chunk = remain > static_cast<usize>(INT_MAX) ? INT_MAX : static_cast<int>(remain);
        const int r = send(s, reinterpret_cast<const char *>(data.data() + off), chunk, 0);
        if (r == SOCKET_ERROR)
          return fail("send failed: {}", WSAGetLastError());
#else
        const ssize_t r = ::send(s, reinterpret_cast<const char *>(data.data() + off), static_cast<usize>(remain), 0);
        if (r < 0)
          return fail("send failed: {}", errno);
#endif
        if (r == 0)
          return fail("send returned 0");
        off += static_cast<usize>(r);
      }
      return Result<void>();
    }
  } // namespace

  auto __connection_from_socket(NativeSocket sock) -> Result<Connection>
  {
    if (!native_socket_valid(sock))
      return fail("invalid socket handle");

    auto connection = make_box<Connection_T>();
    connection->sock = sock;
    return connection;
  }

  auto connection_send(Connection &connection, Span<const u8> data) -> Result<void>
  {
    return send_all(connection->sock, data);
  }

  auto connection_receive(Connection &connection, usize size) -> Result<Vec<u8>>
  {
    if (size == 0)
      return Vec<u8>{};

    Vec<u8> buf;
    buf.resize(size);

#if AU_PLATFORM_WINDOWS
    const int to_recv = size > static_cast<usize>(INT_MAX) ? INT_MAX : static_cast<int>(size);
    const int n = recv(connection->sock, reinterpret_cast<char *>(buf.data()), to_recv, 0);
    if (n == SOCKET_ERROR)
      return fail("recv failed: {}", WSAGetLastError());
#else
    const ssize_t n = ::recv(connection->sock, reinterpret_cast<char *>(buf.data()), static_cast<usize>(size), 0);
    if (n < 0)
      return fail("recv failed: {}", errno);
#endif

    buf.resize(static_cast<usize>(n));
    return buf;
  }
} // namespace ianet
