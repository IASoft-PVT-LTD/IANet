/**
 * @file connection.cpp
 * @brief Connection lifecycle, plain-socket I/O, and TLS session bridging.
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
#  include <netinet/in.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

#include <chrono>
#include <climits>
#include <cstddef>

/// @cond INTERNAL
extern "C"
{
  void ianet_tls_session_free(void *tls);
  int ianet_tls_session_send(void *tls, const unsigned char *data, size_t len, char *error_buf, size_t error_buf_len);
  int ianet_tls_session_recv(void *tls, unsigned char *buf, size_t len, size_t *out_read, char *error_buf,
                             size_t error_buf_len);
}
/// @endcond

module ianet;

namespace ianet
{
  using namespace au;

  namespace
  {
    auto send_all_raw(NativeSocket s, Span<const u8> data) -> Result<void>
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

    auto wait_for_socket_event(NativeSocket s, short events, u32 timeout_ms) -> Result<bool>
    {
      using Clock = std::chrono::steady_clock;
      const Clock::time_point deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
      for (;;)
      {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        const int wait_ms = remaining <= 0 ? 0 : (remaining > INT_MAX ? INT_MAX : static_cast<int>(remaining));
#if AU_PLATFORM_WINDOWS
        WSAPOLLFD descriptor{};
        descriptor.fd = s;
        descriptor.events = events;
        const int r = WSAPoll(&descriptor, 1U, wait_ms);
        if (r == SOCKET_ERROR)
          return fail("poll failed: {}", WSAGetLastError());
#else
        pollfd descriptor{};
        descriptor.fd = s;
        descriptor.events = events;
        const int r = ::poll(&descriptor, 1U, wait_ms);
        if (r < 0)
        {
          if (errno == EINTR)
            continue;
          return fail("poll failed: {}", errno);
        }
#endif
        // Error/hangup conditions count as ready so the following socket
        // operation reports the precise failure.
        if (r > 0)
          return true;
        if (Clock::now() >= deadline)
          return false;
      }
    }
  } // namespace

  /// @cond INTERNAL
  Connection_T::~Connection_T()
  {
    if (tls != nullptr)
      __connection_tls_free(tls);
    native_socket_close(sock);
  }

  auto __connection_tls_free(void *tls) -> void
  {
    ianet_tls_session_free(tls);
  }

  auto __connection_attach_tls(Connection &connection, void *tls) -> void
  {
    connection->tls = tls;
  }

  auto __tls_session_send(void *tls, Span<const u8> data) -> Result<void>
  {
    char err_buf[256]{};
    const int ret = ianet_tls_session_send(tls, data.data(), data.size(), err_buf, sizeof(err_buf));
    if (ret != 0)
      return fail("TLS send failed: {}", err_buf);

    return Result<void>();
  }

  auto __tls_session_recv(void *tls, usize size) -> Result<Vec<u8>>
  {
    if (size == 0)
      return Vec<u8>{};

    Vec<u8> buf;
    buf.resize(size);

    size_t total = 0;
    char err_buf[256]{};
    const int ret = ianet_tls_session_recv(tls, buf.data(), size, &total, err_buf, sizeof(err_buf));
    if (ret != 0)
      return fail("TLS recv failed: {}", err_buf);

    buf.resize(total);
    return buf;
  }

  auto __connection_from_socket(NativeSocket sock) -> Result<Connection>
  {
    if (!native_socket_valid(sock))
      return fail("invalid socket handle");

    auto connection = make_box<Connection_T>();
    connection->sock = sock;
    return connection;
  }

  /// @endcond

  auto connection_send(Connection &connection, Span<const u8> data) -> Result<void>
  {
    if (connection->tls != nullptr)
      return __tls_session_send(connection->tls, data);

    return send_all_raw(connection->sock, data);
  }

  auto connection_receive(Connection &connection, usize size) -> Result<Vec<u8>>
  {
    if (connection->tls != nullptr)
      return __tls_session_recv(connection->tls, size);

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

  auto connection_wait_readable(Connection &connection, u32 timeout_ms) -> Result<bool>
  {
    return wait_for_socket_event(connection->sock, POLLIN, timeout_ms);
  }

  auto connection_wait_writable(Connection &connection, u32 timeout_ms) -> Result<bool>
  {
    return wait_for_socket_event(connection->sock, POLLOUT, timeout_ms);
  }
} // namespace ianet
