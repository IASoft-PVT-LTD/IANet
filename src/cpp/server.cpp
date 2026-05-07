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
#include <ianet_server.hpp>

#if AU_PLATFORM_LINUX
#  include <cerrno>
#endif

namespace ianet
{
  auto create_server(Context &ctx, u16 port) -> Result<Server>
  {
    (void) ctx;

#if AU_PLATFORM_WINDOWS
    const NativeSocket listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET)
      return fail("socket failed: %d", WSAGetLastError());
#else
    const NativeSocket listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (!native_socket_valid(listen_sock))
      return fail("socket failed: %d", errno);
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
      return fail("setsockopt SO_REUSEADDR failed: %d", err);
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
      return fail("bind failed: %d", err);
    }

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
      return fail("listen failed: %d", err);
    }

    HeapAllocator alloc;
    void *mem = alloc.alloc(sizeof(Server_T), alignof(Server_T));
    if (!mem)
    {
      native_socket_close(listen_sock);
      return fail("failed to allocate server");
    }

    const auto server = new (mem) Server_T();
    server->sock = listen_sock;

    return Box<Server_T, Deleter_Server_T<HeapAllocator>>(server, Deleter_Server_T<HeapAllocator>(alloc));
  }

  auto __internal_destory_server(HeapAllocator *allocator, Server_T *server) -> void
  {
    if (!server)
      return;

    native_socket_close(server->sock);

    server->~Server_T();
    allocator->free(server, sizeof(Server_T), alignof(Server_T));
  }

  auto server_accept(Server &server) -> Result<Connection>
  {
#if AU_PLATFORM_WINDOWS
    const NativeSocket client_sock = accept(server->sock, nullptr, nullptr);
    if (client_sock == INVALID_SOCKET)
      return fail("accept failed: %d", WSAGetLastError());
#else
    const NativeSocket client_sock = ::accept(server->sock, nullptr, nullptr);
    if (!native_socket_valid(client_sock))
      return fail("accept failed: %d", errno);
#endif

    auto conn = __connection_from_socket(client_sock);
    if (conn.is_err())
      native_socket_close(client_sock);
    return conn;
  }
} // namespace ianet
