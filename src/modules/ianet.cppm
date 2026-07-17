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

#include <cstddef>

/// @cond INTERNAL
extern "C"
{
  void ianet_tls_session_free(void *tls);
  int ianet_tls_session_send(void *tls, const unsigned char *data, size_t len, char *error_buffer,
                             size_t error_buffer_size);
  int ianet_tls_session_recv(void *tls, unsigned char *buf, size_t len, size_t *out_read, char *error_buffer,
                             size_t error_buffer_size);
}
/// @endcond

/**
 * @file ianet.cppm
 * @brief Core IANet module — cross-platform sockets and connections.
 *
 * Provides context lifecycle, TCP/UDP clients and servers, and byte-stream I/O.
 * Re-exports the Auxid platform library (`export import auxid`).
 */

export module ianet;

export import auxid;

export namespace ianet
{
  using namespace au;

#if AU_PLATFORM_WINDOWS
  /** @brief Platform-native socket handle (`SOCKET` on Windows). */
  using NativeSocket = SOCKET;
#else
  /** @brief Platform-native socket handle (file descriptor on Linux). */
  using NativeSocket = int;
#endif

  /**
   * @brief Returns whether @p s is a usable socket handle.
   * @param s Native socket handle to test.
   */
  [[nodiscard]] inline auto native_socket_valid(NativeSocket s) -> bool
  {
#if AU_PLATFORM_WINDOWS
    return s != INVALID_SOCKET;
#else
    return s >= 0;
#endif
  }

  /**
   * @brief Closes @p s if it is currently valid.
   * @param s Native socket handle to close.
   */
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

  /** @brief Transport protocol for socket clients and servers. */
  enum class EProtocolType
  {
    TCP = 0, ///< Connection-oriented stream sockets.
    UDP = 1, ///< Datagram sockets (accept is not supported on UDP servers).
  };

  /// @cond INTERNAL
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
    void *tls{};

    ~Connection_T();
  };

  /// @endcond

  /** @brief Opaque networking context (initializes Winsock on Windows). */
  using Context = Box<Context_T>;
  /** @brief Opaque socket client handle. */
  using SocketClient = Box<SocketClient_T>;
  /** @brief Opaque listening socket server handle. */
  using SocketServer = Box<SocketServer_T>;
  /** @brief Opaque connected socket (plain or TLS-wrapped). */
  using Connection = Box<Connection_T>;

  /**
   * @brief Creates a networking context.
   *
   * On Windows, initializes Winsock; cleanup runs when the context is destroyed.
   *
   * @return A new context on success.
   */
  auto create_context() -> Result<Context>;

  /**
   * @brief Creates a socket client for the given protocol.
   * @param ctx   Active networking context.
   * @param protocol  TCP or UDP.
   * @return A new client handle on success.
   */
  auto create_socket_client(Context &ctx, EProtocolType protocol) -> Result<SocketClient>;

  /**
   * @brief Creates and binds a listening socket server.
   * @param ctx   Active networking context.
   * @param protocol  TCP or UDP.
   * @param port  Local port to bind (IPv4, all interfaces).
   * @return A new server handle on success.
   */
  auto create_socket_server(Context &ctx, EProtocolType protocol, u16 port) -> Result<SocketServer>;

  /**
   * @brief Connects a client to a remote IPv4 host.
   * @param client  Client created with @ref create_socket_client.
   * @param address IPv4 address string (e.g. `"127.0.0.1"`).
   * @param port    Remote port.
   * @return A connected @ref Connection on success.
   */
  auto socket_client_connect(SocketClient &client, const String &address, u16 port) -> Result<Connection>;

  /**
   * @brief Accepts an incoming connection on a TCP server.
   * @param server  TCP server created with @ref create_socket_server.
   * @return A new @ref Connection for the accepted peer.
   */
  auto socket_server_accept(SocketServer &server) -> Result<Connection>;

  /**
   * @brief Sends bytes on a connection (plain socket or TLS session).
   * @param connection  Active connection.
   * @param data        Bytes to send.
   */
  auto connection_send(Connection &connection, Span<const u8> data) -> Result<void>;

  /**
   * @brief Receives up to @p size bytes from a connection.
   * @param connection  Active connection.
   * @param size        Maximum number of bytes to read.
   * @return Received bytes (may be fewer than @p size).
   */
  auto connection_receive(Connection &connection, usize size) -> Result<Vec<u8>>;
} // namespace ianet

/// @cond INTERNAL
namespace ianet
{
  using namespace au;
  auto __connection_from_socket(NativeSocket sock) -> Result<Connection>;
  auto __connection_attach_tls(Connection &connection, void *tls) -> void;
  auto __connection_tls_free(void *tls) -> void;
  auto __tls_session_send(void *tls, Span<const u8> data) -> Result<void>;
  auto __tls_session_recv(void *tls, usize size) -> Result<Vec<u8>>;
} // namespace ianet

/// @endcond
