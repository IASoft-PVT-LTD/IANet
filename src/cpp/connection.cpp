// IANet: Cross-Platform Networking Library for C++
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <ianet_connection.hpp>

#if AU_PLATFORM_LINUX
#  include <cerrno>
#endif

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
          return fail("send failed: %d", WSAGetLastError());
#else
        const ssize_t r = ::send(s, reinterpret_cast<const char *>(data.data() + off), static_cast<usize>(remain), 0);
        if (r < 0)
          return fail("send failed: %d", errno);
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

    HeapAllocator alloc;
    void *mem = alloc.alloc(sizeof(Connection_T), alignof(Connection_T));
    if (!mem)
      return fail("failed to allocate connection");

    const auto connection = new (mem) Connection_T();
    connection->sock = sock;

    return Box<Connection_T, Deleter_Connection_T<HeapAllocator>>(connection,
                                                                  Deleter_Connection_T<HeapAllocator>(alloc));
  }

  auto __internal_destory_connection(HeapAllocator *allocator, Connection_T *connection) -> void
  {
    if (!connection)
      return;

    native_socket_close(connection->sock);

    connection->~Connection_T();
    allocator->free(connection, sizeof(Connection_T), alignof(Connection_T));
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
      return fail("recv failed: %d", WSAGetLastError());
#else
    const ssize_t n = ::recv(connection->sock, reinterpret_cast<char *>(buf.data()), static_cast<usize>(size), 0);
    if (n < 0)
      return fail("recv failed: %d", errno);
#endif

    buf.resize(static_cast<usize>(n));
    return buf;
  }
} // namespace ianet
