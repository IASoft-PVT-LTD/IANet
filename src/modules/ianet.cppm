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
#  pragma comment(lib, "ws2_32.lib")
#elif AU_PLATFORM_LINUX
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

export module ianet;

export import auxid;

export namespace ianet
{
  using namespace au;

#if AU_PLATFORM_WINDOWS
  using NativeSocket = SOCKET;
#else
  using NativeSocket = int;
#endif

  [[nodiscard]] inline auto native_socket_valid(NativeSocket s) -> bool
  {
#if AU_PLATFORM_WINDOWS
    return s != INVALID_SOCKET;
#else
    return s >= 0;
#endif
  }

  inline auto native_socket_close(NativeSocket s) -> void
  {
#if AU_PLATFORM_WINDOWS
    if (s != INVALID_SOCKET)
      closesocket(s);
#else
    if (s >= 0)
      ::close(s);
#endif
  }

  enum class EProtocolType
  {
    TCP = 0,
    UDP = 1,
  };

  struct Context_T
  {
    ~Context_T()
    {
#if AU_PLATFORM_WINDOWS
      WSACleanup();
#endif
    }
  };

  struct SocketClient_T
  {
    EProtocolType protocol{};
  };

  struct SocketServer_T
  {
    NativeSocket sock{};
    EProtocolType protocol{};
    u16 port{};

    ~SocketServer_T()
    {
      native_socket_close(sock);
    }
  };

  struct Connection_T
  {
    NativeSocket sock{};

    ~Connection_T()
    {
      native_socket_close(sock);
    }
  };

  using Context = Box<Context_T>;
  using SocketClient = Box<SocketClient_T>;
  using SocketServer = Box<SocketServer_T>;
  using Connection = Box<Connection_T>;

  auto create_context() -> Result<Context>;

  auto create_socket_client(Context &ctx, EProtocolType protocol) -> Result<SocketClient>;
  auto create_socket_server(Context &ctx, EProtocolType protocol, u16 port) -> Result<SocketServer>;

  auto socket_client_connect(SocketClient &client, const String &address, u16 port) -> Result<Connection>;
  auto socket_server_accept(SocketServer &server) -> Result<Connection>;

  auto connection_send(Connection &connection, Span<const u8> data) -> Result<void>;
  auto connection_receive(Connection &connection, usize size) -> Result<Vec<u8>>;
} // namespace ianet

namespace ianet
{
  using namespace au;
  auto __connection_from_socket(NativeSocket sock) -> Result<Connection>;
}
