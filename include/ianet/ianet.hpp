// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the PolyForm Noncommercial License 1.0.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://polyformproject.org/licenses/noncommercial/1.0.0>.

#pragma once

#include <ianet/definitions.hpp>

namespace ianet
{
  using Context = Box<Context_T, Deleter_Context_T<HeapAllocator>>;
  using SocketClient = Box<SocketClient_T, Deleter_SocketClient_T<HeapAllocator>>;
  using SocketServer = Box<SocketServer_T, Deleter_SocketServer_T<HeapAllocator>>;
  using Connection = Box<Connection_T, Deleter_Connection_T<HeapAllocator>>;
  using HttpClient = Box<HttpClient_T, Deleter_HttpClient_T<HeapAllocator>>;
  using HttpServer = Box<HttpServer_T, Deleter_HttpServer_T<HeapAllocator>>;
  using HttpConnection = Box<HttpConnection_T, Deleter_HttpConnection_T<HeapAllocator>>;

  auto create_context() -> Result<Context>;

  auto create_socket_client(Context &ctx, EProtocolType protocol) -> Result<SocketClient>;
  auto create_socket_server(Context &ctx, EProtocolType protocol, u16 port) -> Result<SocketServer>;

  auto socket_client_connect(SocketClient &client, const String &address, u16 port) -> Result<Connection>;
  auto socket_server_accept(SocketServer &server) -> Result<Connection>;

  auto connection_send(Connection &connection, Span<const u8> data) -> Result<void>;
  auto connection_receive(Connection &connection, usize size) -> Result<Vec<u8>>;

  auto create_http_client(Context &ctx) -> Result<HttpClient>;
  auto create_http_server(Context &ctx, u16 port) -> Result<HttpServer>;

  auto http_client_connect(HttpClient &client, const String &address, u16 port) -> Result<HttpConnection>;
  auto http_server_accept(HttpServer &server) -> Result<HttpConnection>;

  auto http_connection_send_request(HttpConnection &conn, const HttpRequest &req) -> Result<void>;
  auto http_connection_receive_response(HttpConnection &conn) -> Result<HttpResponse>;
  auto http_connection_receive_request(HttpConnection &conn) -> Result<HttpRequest>;
  auto http_connection_send_response(HttpConnection &conn, const HttpResponse &res) -> Result<void>;
} // namespace ianet
