// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the PolyForm Noncommercial License 1.0.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://polyformproject.org/licenses/noncommercial/1.0.0>.

#include <ianet_client.hpp>
#include <ianet_connection.hpp>

#if AU_PLATFORM_LINUX
#  include <cerrno>
#endif

namespace ianet
{
  auto create_client(Context &ctx) -> Result<Client>
  {
    (void) ctx;

    HeapAllocator alloc;
    void *mem = alloc.alloc(sizeof(Client_T), alignof(Client_T));
    if (!mem)
      return fail("failed to allocate client");

    const auto client = new (mem) Client_T();

    return Box<Client_T, Deleter_Client_T<HeapAllocator>>(client, Deleter_Client_T<HeapAllocator>(alloc));
  }

  auto __internal_destory_client(HeapAllocator *allocator, Client_T *client) -> void
  {
    if (!client)
      return;

    client->~Client_T();
    allocator->free(client, sizeof(Client_T), alignof(Client_T));
  }

  auto client_connect(Client &client, const String &address, u16 port) -> Result<Connection>
  {
    (void) client;

#if AU_PLATFORM_WINDOWS
    const NativeSocket s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
      return fail("socket failed: %d", WSAGetLastError());
#else
    const NativeSocket s = socket(AF_INET, SOCK_STREAM, 0);
    if (!native_socket_valid(s))
      return fail("socket failed: %d", errno);
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
      return fail("connect failed: %d", err);
    }

    auto conn = __connection_from_socket(s);
    if (conn.is_err())
      native_socket_close(s);
    return conn;
  }
} // namespace ianet
