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
} // namespace ianet
