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

export module ianet.http;

export import ianet;

export namespace ianet
{
  using namespace au;

  struct HttpRequest
  {
    String method;
    String path;
    int minor_version;
    Vec<Pair<String, String>> headers;
    Vec<u8> body;
  };

  struct HttpResponse
  {
    int minor_version;
    u16 status_code;
    String status_message;
    Vec<Pair<String, String>> headers;
    Vec<u8> body;
  };

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

  using HttpClient = Box<HttpClient_T>;
  using HttpServer = Box<HttpServer_T>;
  using HttpConnection = Box<HttpConnection_T>;

  auto create_http_client(Context &ctx) -> Result<HttpClient>;
  auto create_http_server(Context &ctx, u16 port) -> Result<HttpServer>;

  auto http_client_connect(HttpClient &client, const String &address, u16 port) -> Result<HttpConnection>;
  auto http_server_accept(HttpServer &server) -> Result<HttpConnection>;

  auto http_connection_send_request(HttpConnection &conn, const HttpRequest &req) -> Result<void>;
  auto http_connection_receive_response(HttpConnection &conn) -> Result<HttpResponse>;
  auto http_connection_receive_request(HttpConnection &conn) -> Result<HttpRequest>;
  auto http_connection_send_response(HttpConnection &conn, const HttpResponse &res) -> Result<void>;
} // namespace ianet
