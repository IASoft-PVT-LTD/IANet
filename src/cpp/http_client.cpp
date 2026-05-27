// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the PolyForm Noncommercial License 1.0.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://polyformproject.org/licenses/noncommercial/1.0.0>.

module;

#include <utility>

module ianet.http;

namespace ianet
{
  auto create_http_client(Context &ctx) -> Result<HttpClient>
  {
    (void) ctx;
    return make_box<HttpClient_T>();
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
      return fail("failed to create socket client: {}", sock_cli_r.error());

    auto sock_cli = std::move(sock_cli_r.unwrap());

    auto conn_r = socket_client_connect(sock_cli, address, port);
    if (conn_r.is_err())
      return fail("failed to connect: {}", conn_r.error());

    auto http_conn = make_box<HttpConnection_T>();
    http_conn->conn = std::move(conn_r.unwrap());
    return http_conn;
  }
} // namespace ianet
