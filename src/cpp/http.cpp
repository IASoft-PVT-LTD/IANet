/**
 * @file http.cpp
 * @brief HTTP/1.x client, server, and message parse/serialize implementation.
 */

// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the PolyForm Noncommercial License 1.0.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://polyformproject.org/licenses/noncommercial/1.0.0>.

module;

#include <string>
#include <utility>

#include <vendor/picohttpparser/picohttpparser.h>

module ianet.http;

namespace ianet
{
  using namespace au;

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

    usize content_length = 0;
    for (size_t i = 0; i != num_headers; ++i)
    {
      String name(headers[i].name, headers[i].name_len);
      String value(headers[i].value, headers[i].value_len);
      res.headers.push_back(Pair<String, String>(name, value));

      if (name.size() == 14)
      {
        bool match = true;
        const char *cl = "content-length";
        for (usize j = 0; j < 14; ++j)
        {
          char c = name.data()[j];
          if (c >= 'A' && c <= 'Z')
            c += 32;
          if (c != cl[j])
          {
            match = false;
            break;
          }
        }
        if (match)
        {
          content_length = std::stoull(value.c_str());
        }
      }
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

    while (res.body.size() < content_length)
    {
      usize to_read = content_length - res.body.size();
      auto recv_r = connection_receive(conn->conn, to_read);
      if (recv_r.is_err())
        return fail(std::move(recv_r.unwrap_err()).ctx("failed to receive body"));

      auto chunk = std::move(recv_r.unwrap());
      if (chunk.empty())
        return fail("connection closed by peer while reading body");

      res.body.reserve(res.body.size() + chunk.size());
      for (auto b : chunk)
      {
        res.body.push_back(b);
      }
    }

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

    usize content_length = 0;
    for (size_t i = 0; i != num_headers; ++i)
    {
      String name(headers[i].name, headers[i].name_len);
      String value(headers[i].value, headers[i].value_len);
      req.headers.push_back(Pair<String, String>(name, value));

      if (name.size() == 14)
      {
        bool match = true;
        const char *cl = "content-length";
        for (usize j = 0; j < 14; ++j)
        {
          char c = name.data()[j];
          if (c >= 'A' && c <= 'Z')
            c += 32;
          if (c != cl[j])
          {
            match = false;
            break;
          }
        }
        if (match)
        {
          content_length = std::stoull(value.c_str());
        }
      }
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

    while (req.body.size() < content_length)
    {
      usize to_read = content_length - req.body.size();
      auto recv_r = connection_receive(conn->conn, to_read);
      if (recv_r.is_err())
        return fail(std::move(recv_r.unwrap_err()).ctx("failed to receive body"));

      auto chunk = std::move(recv_r.unwrap());
      if (chunk.empty())
        return fail("connection closed by peer while reading body");

      req.body.reserve(req.body.size() + chunk.size());
      for (auto b : chunk)
      {
        req.body.push_back(b);
      }
    }

    return req;
  }
} // namespace ianet
