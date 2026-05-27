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
  auto create_http_server(Context &ctx, u16 port) -> Result<HttpServer>
  {
    auto sock_srv_r = create_socket_server(ctx, EProtocolType::TCP, port);
    if (sock_srv_r.is_err())
      return fail("failed to create socket server: {}", sock_srv_r.error());

    auto server = make_box<HttpServer_T>();
    server->sock_server = std::move(sock_srv_r.unwrap());
    return server;
  }

  auto http_server_accept(HttpServer &server) -> Result<HttpConnection>
  {
    auto conn_r = socket_server_accept(server->sock_server);
    if (conn_r.is_err())
      return fail("failed to accept connection: {}", conn_r.error());

    auto http_conn = make_box<HttpConnection_T>();
    http_conn->conn = std::move(conn_r.unwrap());
    return http_conn;
  }
} // namespace ianet
