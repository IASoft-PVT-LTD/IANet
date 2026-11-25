/**
 * @file http.cpp
 * @brief HTTP/1.x client, server, and message parse/serialize implementation.
 */

// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the Apache License, Version 2.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://www.apache.org/licenses/LICENSE-2.0>.

module;

#include <algorithm>
#include <charconv>
#include <string_view>
#include <system_error>
#include <utility>

#include <vendor/picohttpparser/picohttpparser.h>

module ianet.http;

namespace ianet
{
  using namespace au;

  namespace
  {
    // Bodies are read in pieces of at most this size, so memory use follows what
    // the peer actually sends and not the length it claims.
    constexpr usize MAX_BODY_CHUNK = 64 * 1024;

    auto is_content_length(std::string_view name) -> bool
    {
      constexpr std::string_view expected = "content-length";
      return std::equal(name.begin(), name.end(), expected.begin(), expected.end(), [](char a, char b) {
        return (a >= 'A' && a <= 'Z' ? static_cast<char>(a + ('a' - 'A')) : a) == b;
      });
    }

    // Returns the body length given by the headers, or 0 when they don't give one.
    // The value has to be digits only, and repeated headers have to agree.
    auto parse_content_length(const phr_header *headers, size_t num_headers) -> Result<usize>
    {
      usize length = 0;
      bool found = false;

      for (size_t i = 0; i != num_headers; ++i)
      {
        if (headers[i].name == nullptr || !is_content_length({headers[i].name, headers[i].name_len}))
          continue;

        const char *first = headers[i].value;
        const char *last = first + headers[i].value_len;

        usize value = 0;
        const auto parsed = std::from_chars(first, last, value);
        if (parsed.ec != std::errc{} || parsed.ptr != last)
          return fail("invalid Content-Length header");
        if (found && value != length)
          return fail("conflicting Content-Length headers");

        length = value;
        found = true;
      }

      return length;
    }

    // Appends to @p body until it holds @p content_length bytes.
    auto receive_body(Connection &conn, Vec<u8> &body, usize content_length) -> Result<void>
    {
      while (body.size() < content_length)
      {
        const usize to_read = std::min(content_length - body.size(), MAX_BODY_CHUNK);
        auto recv_r = connection_receive(conn, to_read);
        if (recv_r.is_err())
          return fail(std::move(recv_r.unwrap_err()).ctx("failed to receive body"));

        auto chunk = std::move(recv_r.unwrap());
        if (chunk.empty())
          return fail("connection closed by peer while reading body");

        body.insert(body.end(), chunk.begin(), chunk.end());
      }

      return Result<void>();
    }
  } // namespace

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
      return fail(std::move(sock_cli_r.unwrap_err()).ctx("failed to create socket client"));

    auto sock_cli = std::move(sock_cli_r.unwrap());

    auto conn_r = socket_client_connect(sock_cli, address, port);
    if (conn_r.is_err())
      return fail(std::move(conn_r.unwrap_err()).ctx("failed to connect"));

    auto http_conn = make_box<HttpConnection_T>();
    http_conn->conn = std::move(conn_r.unwrap());
    return http_conn;
  }

  auto create_http_server(Context &ctx, u16 port) -> Result<HttpServer>
  {
    auto sock_srv_r = create_socket_server(ctx, EProtocolType::TCP, port);
    if (sock_srv_r.is_err())
      return fail(std::move(sock_srv_r.unwrap_err()).ctx("failed to create socket server"));

    auto server = make_box<HttpServer_T>();
    server->sock_server = std::move(sock_srv_r.unwrap());
    return server;
  }

  auto http_server_accept(HttpServer &server) -> Result<HttpConnection>
  {
    auto conn_r = socket_server_accept(server->sock_server);
    if (conn_r.is_err())
      return fail(std::move(conn_r.unwrap_err()).ctx("failed to accept connection"));

    auto http_conn = make_box<HttpConnection_T>();
    http_conn->conn = std::move(conn_r.unwrap());
    return http_conn;
  }

  auto http_connection_send_request(HttpConnection &conn, const HttpRequest &req) -> Result<void>
  {
    String buf;
    buf.append(req.method);
    buf.append(" ");
    buf.append(req.path);
    buf.append(String::format(" HTTP/1.{}\r\n", req.minor_version));

    for (const auto &header : req.headers)
    {
      buf.append(header.first);
      buf.append(": ");
      buf.append(header.second);
      buf.append("\r\n");
    }

    if (!req.body.empty())
    {
      buf.append(String::format("Content-Length: {}\r\n", req.body.size()));
    }
    buf.append("\r\n");

    auto send_r = connection_send(conn->conn, Span<const u8>(reinterpret_cast<const u8 *>(buf.data()), buf.size()));
    if (send_r.is_err())
      return send_r;

    if (!req.body.empty())
    {
      auto send_r2 = connection_send(conn->conn, Span<const u8>(req.body.data(), req.body.size()));
      if (send_r2.is_err())
        return send_r2;
    }

    return Result<void>();
  }

  auto http_connection_send_response(HttpConnection &conn, const HttpResponse &res) -> Result<void>
  {
    String buf;
    buf.append(String::format("HTTP/1.{} {} ", res.minor_version, res.status_code));
    buf.append(res.status_message);
    buf.append("\r\n");

    for (const auto &header : res.headers)
    {
      buf.append(header.first);
      buf.append(": ");
      buf.append(header.second);
      buf.append("\r\n");
    }

    if (!res.body.empty())
    {
      buf.append(String::format("Content-Length: {}\r\n", res.body.size()));
    }
    buf.append("\r\n");

    auto send_r = connection_send(conn->conn, Span<const u8>(reinterpret_cast<const u8 *>(buf.data()), buf.size()));
    if (send_r.is_err())
      return send_r;

    if (!res.body.empty())
    {
      auto send_r2 = connection_send(conn->conn, Span<const u8>(res.body.data(), res.body.size()));
      if (send_r2.is_err())
        return send_r2;
    }

    return Result<void>();
  }

  auto http_connection_receive_response(HttpConnection &conn) -> Result<HttpResponse>
  {
    Vec<u8> buf;
    int minor_version;
    int status;
    const char *msg;
    size_t msg_len;
    struct phr_header headers[100];
    size_t num_headers;
    int pret;

    while (true)
    {
      auto recv_r = connection_receive(conn->conn, 4096);
      if (recv_r.is_err())
        return fail(std::move(recv_r.unwrap_err()).ctx("failed to receive"));

      auto chunk = std::move(recv_r.unwrap());
      if (chunk.empty())
        return fail("connection closed by peer");

      buf.reserve(buf.size() + chunk.size());
      for (auto b : chunk)
      {
        buf.push_back(b);
      }

      num_headers = sizeof(headers) / sizeof(headers[0]);
      pret = phr_parse_response(reinterpret_cast<const char *>(buf.data()), buf.size(), &minor_version, &status, &msg,
                                &msg_len, headers, &num_headers, 0);

      if (pret > 0)
        break;
      else if (pret == -1)
        return fail("failed to parse http response");
    }

    HttpResponse res;
    res.minor_version = minor_version;
    res.status_code = static_cast<u16>(status);
    res.status_message = String(msg, msg_len);

    auto content_length_r = parse_content_length(headers, num_headers);
    if (content_length_r.is_err())
      return fail(std::move(content_length_r.unwrap_err()));

    for (size_t i = 0; i != num_headers; ++i)
    {
      String name(headers[i].name, headers[i].name_len);
      String value(headers[i].value, headers[i].value_len);
      res.headers.push_back(Pair<String, String>(name, value));
    }

    usize header_size = static_cast<usize>(pret);
    usize body_bytes_read = buf.size() - header_size;

    if (body_bytes_read > 0)
    {
      res.body.reserve(res.body.size() + body_bytes_read);
      for (usize i = 0; i < body_bytes_read; ++i)
      {
        res.body.push_back(buf[header_size + i]);
      }
    }

    auto body_r = receive_body(conn->conn, res.body, content_length_r.unwrap());
    if (body_r.is_err())
      return fail(std::move(body_r.unwrap_err()));

    return res;
  }

  auto http_connection_receive_request(HttpConnection &conn) -> Result<HttpRequest>
  {
    Vec<u8> buf;
    const char *method, *path;
    size_t method_len, path_len;
    int minor_version;
    struct phr_header headers[100];
    size_t num_headers;
    int pret;

    while (true)
    {
      auto recv_r = connection_receive(conn->conn, 4096);
      if (recv_r.is_err())
        return fail(std::move(recv_r.unwrap_err()).ctx("failed to receive"));

      auto chunk = std::move(recv_r.unwrap());
      if (chunk.empty())
        return fail("connection closed by peer");

      buf.reserve(buf.size() + chunk.size());
      for (auto b : chunk)
      {
        buf.push_back(b);
      }

      num_headers = sizeof(headers) / sizeof(headers[0]);
      pret = phr_parse_request(reinterpret_cast<const char *>(buf.data()), buf.size(), &method, &method_len, &path,
                               &path_len, &minor_version, headers, &num_headers, 0);

      if (pret > 0)
        break;
      else if (pret == -1)
        return fail("failed to parse http request");
    }

    HttpRequest req;
    req.method = String(method, method_len);
    req.path = String(path, path_len);
    req.minor_version = minor_version;

    auto content_length_r = parse_content_length(headers, num_headers);
    if (content_length_r.is_err())
      return fail(std::move(content_length_r.unwrap_err()));

    for (size_t i = 0; i != num_headers; ++i)
    {
      String name(headers[i].name, headers[i].name_len);
      String value(headers[i].value, headers[i].value_len);
      req.headers.push_back(Pair<String, String>(name, value));
    }

    usize header_size = static_cast<usize>(pret);
    usize body_bytes_read = buf.size() - header_size;

    if (body_bytes_read > 0)
    {
      req.body.reserve(req.body.size() + body_bytes_read);
      for (usize i = 0; i < body_bytes_read; ++i)
      {
        req.body.push_back(buf[header_size + i]);
      }
    }

    auto body_r = receive_body(conn->conn, req.body, content_length_r.unwrap());
    if (body_r.is_err())
      return fail(std::move(body_r.unwrap_err()));

    return req;
  }
} // namespace ianet
