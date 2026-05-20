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
  auto create_http_client(Context &ctx) -> Result<HttpClient>
  {
    HeapAllocator alloc;
    void *mem = alloc.alloc(sizeof(HttpClient_T), alignof(HttpClient_T));
    if (!mem)
      return fail("failed to allocate http client");

    const auto client = new (mem) HttpClient_T();
    
    // We need to clone the context or just store a reference.
    // Wait, Context is a Box. We can't easily clone a Box without a clone method.
    // Let's just create a new context or pass it by reference? 
    // Actually, we can just store a raw pointer to Context_T if we need it, but we can't do that safely.
    // Let's look at how Context is used.
    // In create_socket_client, Context is just passed and ignored `(void) ctx;`.
    // So we don't even need to store it!
    (void) ctx;

    return Box<HttpClient_T, Deleter_HttpClient_T<HeapAllocator>>(client, Deleter_HttpClient_T<HeapAllocator>(alloc));
  }

  auto __internal_destory_http_client(HeapAllocator *allocator, HttpClient_T *client) -> void
  {
    if (!client)
      return;

    client->~HttpClient_T();
    allocator->free(client, sizeof(HttpClient_T), alignof(HttpClient_T));
  }

  auto http_client_connect(HttpClient &client, const String &address, u16 port) -> Result<HttpConnection>
  {
    (void) client;
    
    auto ctx_r = create_context();
    if (ctx_r.is_err())
      return fail("failed to create context for http client connect");
    auto ctx = std::move(ctx_r.unwrap());

    auto sock_cli_r = create_socket_client(ctx, EProtocolType::TCP);
    if (sock_cli_r.is_err())
      return fail("failed to create socket client: %s", sock_cli_r.error().c_str());
    
    auto sock_cli = std::move(sock_cli_r.unwrap());

    auto conn_r = socket_client_connect(sock_cli, address, port);
    if (conn_r.is_err())
      return fail("failed to connect: %s", conn_r.error().c_str());

    HeapAllocator alloc;
    void *mem = alloc.alloc(sizeof(HttpConnection_T), alignof(HttpConnection_T));
    if (!mem)
      return fail("failed to allocate http connection");

    const auto http_conn = new (mem) HttpConnection_T();
    http_conn->conn = std::move(conn_r.unwrap());

    return Box<HttpConnection_T, Deleter_HttpConnection_T<HeapAllocator>>(http_conn, Deleter_HttpConnection_T<HeapAllocator>(alloc));
  }
} // namespace ianet
