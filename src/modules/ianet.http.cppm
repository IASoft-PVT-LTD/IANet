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

/**
 * @file ianet.http.cppm
 * @brief HTTP/1.x client and server module.
 *
 * Builds on the core @ref ianet module for TCP connections and provides
 * request/response types plus send/receive helpers.
 */

export module ianet.http;
export import ianet;

export namespace ianet

{
  using namespace au;

  /** @brief HTTP/1.x request message. */
  struct HttpRequest
  {
    String method;                     ///< Request method (e.g. `"GET"`, `"POST"`).
    String path;                       ///< Request target path (e.g. `"/api/ping"`).
    int minor_version;                 ///< HTTP minor version (0 or 1).
    Vec<Pair<String, String>> headers; ///< Header field name/value pairs.
    Vec<u8> body;                      ///< Optional request body.
  };

  /** @brief HTTP/1.x response message. */
  struct HttpResponse
  {
    int minor_version;                 ///< HTTP minor version (0 or 1).
    u16 status_code;                   ///< Numeric status code (e.g. 200).
    String status_message;             ///< Reason phrase (e.g. `"OK"`).
    Vec<Pair<String, String>> headers; ///< Header field name/value pairs.
    Vec<u8> body;                      ///< Optional response body.
  };

  /// @cond INTERNAL
  struct HttpClient_T
  {
  };

  struct HttpServer_T
  {
    Box<SocketServer_T> sock_server;
  };

  struct HttpConnection_T
  {
    Box<Connection_T> conn;
  };

  /// @endcond

  /** @brief Opaque HTTP client handle. */
  using HttpClient = Box<HttpClient_T>;

  /** @brief Opaque HTTP server handle. */
  using HttpServer = Box<HttpServer_T>;

  /** @brief Opaque HTTP connection wrapping a TCP (or TLS) @ref Connection. */
  using HttpConnection = Box<HttpConnection_T>;

  /**
   * @brief Creates an HTTP client.
   * @param ctx  Active networking context.
   */
  auto create_http_client(Context &ctx) -> Result<HttpClient>;

  /**
   * @brief Creates an HTTP server listening on @p port.
   * @param ctx   Active networking context.
   * @param port  Local TCP port.
   */
  auto create_http_server(Context &ctx, u16 port) -> Result<HttpServer>;

  /**
   * @brief Opens a plain HTTP connection to a remote host.
   * @param client   HTTP client (currently unused; a transient socket client is created).
   * @param address  IPv4 address string.
   * @param port     Remote port.
   */
  auto http_client_connect(HttpClient &client, const String &address, u16 port) -> Result<HttpConnection>;

  /**
   * @brief Accepts an incoming HTTP connection on a server.
   * @param server  HTTP server created with @ref create_http_server.
   */
  auto http_server_accept(HttpServer &server) -> Result<HttpConnection>;

  /**
   * @brief Serializes and sends an HTTP request.
   * @param conn  Active HTTP connection.
   * @param req   Request to send; `Content-Length` is added when @p req has a body.
   */
  auto http_connection_send_request(HttpConnection &conn, const HttpRequest &req) -> Result<void>;

  /**
   * @brief Receives and parses an HTTP response.
   * @param conn  Active HTTP connection.
   * @return Parsed response including body (reads until `Content-Length` is satisfied).
   */
  auto http_connection_receive_response(HttpConnection &conn) -> Result<HttpResponse>;

  /**
   * @brief Receives and parses an HTTP request.
   * @param conn  Active HTTP connection (typically from @ref http_server_accept).
   */
  auto http_connection_receive_request(HttpConnection &conn) -> Result<HttpRequest>;

  /**
   * @brief Serializes and sends an HTTP response.
   * @param conn  Active HTTP connection.
   * @param res   Response to send; `Content-Length` is added when @p res has a body.
   */
  auto http_connection_send_response(HttpConnection &conn, const HttpResponse &res) -> Result<void>;
} // namespace ianet
