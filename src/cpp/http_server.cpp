// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the PolyForm Noncommercial License 1.0.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://polyformproject.org/licenses/noncommercial/1.0.0>.

#include <ianet_http.hpp>

namespace ianet
{
  auto create_http_server(Context &ctx, u16 port) -> Result<HttpServer>
  {
    auto sock_srv_r = create_socket_server(ctx, EProtocolType::TCP, port);
    if (sock_srv_r.is_err())
      return fail("failed to create socket server: %s", sock_srv_r.error().c_str());

    HeapAllocator alloc;
    void *mem = alloc.alloc(sizeof(HttpServer_T), alignof(HttpServer_T));
    if (!mem)
      return fail("failed to allocate http server");

    const auto server = new (mem) HttpServer_T();
    server->sock_server = std::move(sock_srv_r.unwrap());

    return Box<HttpServer_T, Deleter_HttpServer_T<HeapAllocator>>(server, Deleter_HttpServer_T<HeapAllocator>(alloc));
  }

  auto __internal_destory_http_server(HeapAllocator *allocator, HttpServer_T *server) -> void
  {
    if (!server)
      return;

    server->~HttpServer_T();
    allocator->free(server, sizeof(HttpServer_T), alignof(HttpServer_T));
  }

  auto http_server_accept(HttpServer &server) -> Result<HttpConnection>
  {
    auto conn_r = socket_server_accept(server->sock_server);
    if (conn_r.is_err())
      return fail("failed to accept connection: %s", conn_r.error().c_str());

    HeapAllocator alloc;
    void *mem = alloc.alloc(sizeof(HttpConnection_T), alignof(HttpConnection_T));
    if (!mem)
      return fail("failed to allocate http connection");

    const auto http_conn = new (mem) HttpConnection_T();
    http_conn->conn = std::move(conn_r.unwrap());

    return Box<HttpConnection_T, Deleter_HttpConnection_T<HeapAllocator>>(http_conn, Deleter_HttpConnection_T<HeapAllocator>(alloc));
  }
} // namespace ianet
