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
#include <utility>

/**
 * @file ianet.https.cppm
 * @brief HTTPS convenience helpers combining HTTP and TLS modules.
 *
 * Wraps @ref ianet.http and @ref ianet.tls for common server/client setup patterns.
 */

export module ianet.https;
export import ianet.http;
export import ianet.tls;

export namespace ianet
{
  using namespace au;

  /// @cond INTERNAL
  struct HttpsServer_T
  {
    Box<SocketServer_T> sock_server;
    TlsContext *tls{};
  };
  /// @endcond

  /** @brief Opaque HTTPS server (TCP listener + TLS context reference). */
  using HttpsServer = Box<HttpsServer_T>;

  /**
   * @brief Creates an HTTPS server listening on @p port.
   * @param ctx   Active networking context.
   * @param port  Local TCP port.
   * @param tls   Server TLS context (must outlive the server).
   */
  inline auto create_https_server(Context &ctx, u16 port, TlsContext &tls) -> Result<HttpsServer>
  {
    auto sock_srv_r = create_socket_server(ctx, EProtocolType::TCP, port);

    if (sock_srv_r.is_err())
      return fail(std::move(sock_srv_r.unwrap_err()).ctx("failed to create socket server"));

    auto server = make_box<HttpsServer_T>();
    server->sock_server = std::move(sock_srv_r.unwrap());
    server->tls = &tls;

    return server;
  }

  /**
   * @brief Accepts an incoming HTTPS connection and completes the TLS handshake.
   * @param server  HTTPS server from @ref create_https_server.
   * @return An @ref HttpConnection ready for HTTP request/response I/O.
   */
  inline auto https_server_accept(HttpsServer &server) -> Result<HttpConnection>
  {
    if (server->tls == nullptr)
      return fail("HTTPS server has no TLS context");

    auto conn_r = tls_server_accept(server->sock_server, *server->tls);
    if (conn_r.is_err())
      return fail(std::move(conn_r.unwrap_err()).ctx("failed to accept TLS connection"));

    auto http_conn = make_box<HttpConnection_T>();
    http_conn->conn = std::move(conn_r.unwrap());

    return http_conn;
  }

  /**
   * @brief Connects to a remote HTTPS host and completes the TLS handshake.
   * @param client   HTTP client (currently unused; a transient client is created).
   * @param address  IPv4 address string.
   * @param port     Remote port.
   * @param tls      Client TLS context.
   */
  inline auto https_client_connect(HttpClient &client, const String &address, u16 port, TlsContext &tls)
      -> Result<HttpConnection>
  {
    (void) client;

    auto ctx_r = create_context();
    if (ctx_r.is_err())
      return fail("failed to create context for https client connect");

    auto connect_ctx = std::move(ctx_r.unwrap());

    auto sock_cli_r = create_socket_client(connect_ctx, EProtocolType::TCP);

    if (sock_cli_r.is_err())
      return fail(std::move(sock_cli_r.unwrap_err()).ctx("failed to create socket client"));

    auto sock_cli = std::move(sock_cli_r.unwrap());

    auto conn_r = tls_client_connect(sock_cli, address, port, tls);

    if (conn_r.is_err())
      return fail(std::move(conn_r.unwrap_err()).ctx("failed to connect"));

    auto http_conn = make_box<HttpConnection_T>();
    http_conn->conn = std::move(conn_r.unwrap());

    return http_conn;
  }
} // namespace ianet
