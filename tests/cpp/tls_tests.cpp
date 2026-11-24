// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the Apache License, Version 2.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://www.apache.org/licenses/LICENSE-2.0>.

#include <atomic>
#include <cstring>
#include <optional>
#include <string>
#include <thread>

import ianet.tls;
import auxid.test;

using namespace au;
using namespace ianet;

namespace
{
  constexpr u16 TLS_EPHEMERAL_BASE = 40120;
  constexpr u16 HTTPS_EPHEMERAL_BASE = 40200;
  constexpr usize TLS_IO_CHUNK = 4096;

  auto bytes_eq(Span<const u8> a, Span<const u8> b) -> bool
  {
    if (a.size() != b.size())
      return false;
    for (usize i = 0; i < a.size(); ++i)
    {
      if (a[i] != b[i])
        return false;
    }
    return true;
  }

  auto buffer_contains(Span<const u8> data, const char *needle) -> bool
  {
    const auto needle_len = std::strlen(needle);
    if (needle_len == 0 || data.size() < needle_len)
      return false;

    for (usize i = 0; i + needle_len <= data.size(); ++i)
    {
      if (std::memcmp(data.data() + i, needle, needle_len) == 0)
        return true;
    }
    return false;
  }

  auto run_tls_echo(u16 port_base, test::Block &block) -> bool
  {
    auto ctx_r = create_context();
    if (!block.check(ctx_r.is_ok(), "create_context().is_ok()"))
      return false;
    auto ctx = std::move(ctx_r.unwrap());

    TlsConfig srv_cfg;
    srv_cfg.cert_file = "tests/fixtures/server.crt";
    srv_cfg.key_file = "tests/fixtures/server.key";
    auto srv_tls_r = create_tls_server_context(srv_cfg);
    if (!block.check(srv_tls_r.is_ok(), "create_tls_server_context().is_ok()"))
      return false;
    auto srv_tls = std::move(srv_tls_r.unwrap());

    TlsConfig cli_cfg;
    cli_cfg.verify_mode = ETlsVerifyMode::Required;
    cli_cfg.ca_file = "tests/fixtures/ca.crt";
    auto cli_tls_r = create_tls_client_context(cli_cfg);
    if (!block.check(cli_tls_r.is_ok(), "create_tls_client_context().is_ok()"))
      return false;
    auto cli_tls = std::move(cli_tls_r.unwrap());

    std::optional<SocketServer> srv_opt;
    u16 port_used = 0;

    for (u16 delta = 0; delta < 48; ++delta)
    {
      const u16 port = static_cast<u16>(port_base + delta);
      auto srv_r = create_socket_server(ctx, EProtocolType::TCP, port);
      if (srv_r.is_ok())
      {
        srv_opt = std::move(srv_r.unwrap());
        port_used = port;
        break;
      }
    }

    if (!block.check(srv_opt.has_value(), "srv_opt.has_value()"))
      return false;

    auto cli_r = create_socket_client(ctx, EProtocolType::TCP);
    if (!block.check(cli_r.is_ok(), "create_socket_client().is_ok()"))
      return false;
    auto cli = std::move(cli_r.unwrap());

    auto srv = std::move(*srv_opt);

    std::atomic<bool> server_ok{true};

    std::thread worker([&srv, &srv_tls, &server_ok]() {
      auto acc_r = tls_server_accept(srv, srv_tls);
      if (!acc_r.is_ok())
      {
        server_ok = false;
        return;
      }
      auto conn_s = std::move(acc_r.unwrap());

      auto recv_r = connection_receive(conn_s, 4);
      if (!recv_r.is_ok())
      {
        server_ok = false;
        return;
      }
      auto got = std::move(recv_r.unwrap());
      if (got.size() != 4)
      {
        server_ok = false;
        return;
      }
      const u8 ping[] = {'p', 'i', 'n', 'g'};
      if (!bytes_eq(Span<const u8>(got.data(), got.size()), Span<const u8>(ping, 4)))
      {
        server_ok = false;
        return;
      }

      const u8 pong[] = {'p', 'o', 'n', 'g'};
      if (connection_send(conn_s, Span<const u8>(pong, 4)).is_err())
        server_ok = false;
    });

    auto conn_c_r = tls_client_connect(cli, String("127.0.0.1"), port_used, cli_tls);
    if (!block.check(conn_c_r.is_ok(), "tls_client_connect().is_ok()"))
      return false;
    auto conn_c = std::move(conn_c_r.unwrap());

    const u8 ping[] = {'p', 'i', 'n', 'g'};
    if (!block.check(connection_send(conn_c, Span<const u8>(ping, 4)).is_ok(), "connection_send(ping).is_ok()"))
      return false;

    auto reply_r = connection_receive(conn_c, 4);
    if (!block.check(reply_r.is_ok(), "connection_receive().is_ok()"))
      return false;
    auto reply = std::move(reply_r.unwrap());
    if (!block.check_eq(reply.size(), static_cast<usize>(4), "reply.size() == 4"))
      return false;

    const u8 pong[] = {'p', 'o', 'n', 'g'};
    if (!block.check(bytes_eq(Span<const u8>(reply.data(), reply.size()), Span<const u8>(pong, 4)), "reply is pong"))
      return false;

    worker.join();
    return block.check(server_ok.load(), "server_ok");
  }

  // Handshake-only probe against the wildcard fixture (`DNS:*.example.test`,
  // self-signed, its own trust anchor). The client dials 127.0.0.1 but asserts the
  // DNS identity `expected_name`; `allow_wildcard` selects the client matching
  // mode. Returns true when the handshake outcome equals `expect_ok`.
  auto run_tls_identity(u16 port_base, test::Block &block, const char *expected_name, bool allow_wildcard,
                        bool expect_ok) -> bool
  {
    auto ctx_r = create_context();
    if (!block.check(ctx_r.is_ok(), "create_context().is_ok()"))
      return false;
    auto ctx = std::move(ctx_r.unwrap());

    TlsConfig srv_cfg;
    srv_cfg.cert_file = "tests/fixtures/wildcard.crt";
    srv_cfg.key_file = "tests/fixtures/wildcard.key";
    auto srv_tls_r = create_tls_server_context(srv_cfg);
    if (!block.check(srv_tls_r.is_ok(), "create_tls_server_context(wildcard).is_ok()"))
      return false;
    auto srv_tls = std::move(srv_tls_r.unwrap());

    TlsConfig cli_cfg;
    cli_cfg.verify_mode = ETlsVerifyMode::Required;
    cli_cfg.ca_file = "tests/fixtures/wildcard.crt";
    cli_cfg.expected_peer_name = String(expected_name);
    cli_cfg.allow_wildcard_peer_names = allow_wildcard;
    auto cli_tls_r = create_tls_client_context(cli_cfg);
    if (!block.check(cli_tls_r.is_ok(), "create_tls_client_context(identity).is_ok()"))
      return false;
    auto cli_tls = std::move(cli_tls_r.unwrap());

    std::optional<SocketServer> srv_opt;
    u16 port_used = 0;
    for (u16 delta = 0; delta < 48; ++delta)
    {
      const u16 port = static_cast<u16>(port_base + delta);
      auto srv_r = create_socket_server(ctx, EProtocolType::TCP, port);
      if (srv_r.is_ok())
      {
        srv_opt = std::move(srv_r.unwrap());
        port_used = port;
        break;
      }
    }
    if (!block.check(srv_opt.has_value(), "srv_opt.has_value()"))
      return false;

    auto cli_r = create_socket_client(ctx, EProtocolType::TCP);
    if (!block.check(cli_r.is_ok(), "create_socket_client().is_ok()"))
      return false;
    auto cli = std::move(cli_r.unwrap());
    auto srv = std::move(*srv_opt);

    // The server side simply completes (or fails) one handshake; a rejected
    // identity surfaces on the client, so the server outcome is not asserted.
    std::thread worker([&srv, &srv_tls]() {
      auto acc_r = tls_server_accept(srv, srv_tls);
      if (acc_r.is_ok())
      {
        auto conn_s = std::move(acc_r.unwrap());
        const u8 pong[] = {'p', 'o', 'n', 'g'};
        (void)connection_send(conn_s, Span<const u8>(pong, 4));
      }
    });

    auto conn_c_r = tls_client_connect(cli, String("127.0.0.1"), port_used, cli_tls);
    const bool ok = conn_c_r.is_ok();
    if (ok)
    {
      auto conn_c = std::move(conn_c_r.unwrap());
      (void)connection_receive(conn_c, 4);
    }
    worker.join();
    return block.check(ok == expect_ok, expect_ok ? "wildcard identity accepted" : "identity rejected");
  }

  struct TlsSuiteBlock final : test::Block
  {
    [[nodiscard]] auto get_name() const -> const char * override
    {
      return "ianet::tls_suite";
    }

    auto declare_tests() -> void override
    {
      add_test("tls_echo_loopback", [this] { return tls_echo_loopback(); });
      add_test("tls_wildcard_rejected_by_default", [this] { return tls_wildcard_rejected_by_default(); });
      add_test("tls_wildcard_accepted_when_enabled", [this] { return tls_wildcard_accepted_when_enabled(); });
      add_test("tls_wildcard_single_label_only", [this] { return tls_wildcard_single_label_only(); });
    }

    auto tls_echo_loopback() -> bool
    {
      return run_tls_echo(TLS_EPHEMERAL_BASE, *this);
    }

    // Default (exact) matching: `*.example.test` must NOT satisfy `api.example.test`.
    auto tls_wildcard_rejected_by_default() -> bool
    {
      return run_tls_identity(static_cast<u16>(TLS_EPHEMERAL_BASE + 400), *this, "api.example.test", false, false);
    }

    // Opt-in wildcard matching: `*.example.test` satisfies `api.example.test`.
    auto tls_wildcard_accepted_when_enabled() -> bool
    {
      return run_tls_identity(static_cast<u16>(TLS_EPHEMERAL_BASE + 448), *this, "api.example.test", true, true);
    }

    // Even with wildcards enabled, `*.example.test` never matches a deeper name.
    auto tls_wildcard_single_label_only() -> bool
    {
      return run_tls_identity(static_cast<u16>(TLS_EPHEMERAL_BASE + 496), *this, "a.b.example.test", true, false);
    }
  };

  struct HttpsSuiteBlock final : test::Block
  {
    [[nodiscard]] auto get_name() const -> const char * override
    {
      return "ianet::https_suite";
    }

    auto declare_tests() -> void override
    {
      add_test("https_ping_pong", [this] { return https_ping_pong(); });
    }

    auto https_ping_pong() -> bool
    {
      const std::string request =
          "POST /ping HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nping";
      const std::string response =
          "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\npong";

      auto ctx_r = create_context();
      if (!check(ctx_r.is_ok(), "create_context().is_ok()"))
        return false;
      auto ctx = std::move(ctx_r.unwrap());

      TlsConfig srv_cfg;
      srv_cfg.cert_file = "tests/fixtures/server.crt";
      srv_cfg.key_file = "tests/fixtures/server.key";
      auto srv_tls_r = create_tls_server_context(srv_cfg);
      if (!check(srv_tls_r.is_ok(), "create_tls_server_context().is_ok()"))
        return false;
      auto srv_tls = std::move(srv_tls_r.unwrap());

      TlsConfig cli_cfg;
      cli_cfg.verify_mode = ETlsVerifyMode::Required;
      cli_cfg.ca_file = "tests/fixtures/ca.crt";
      auto cli_tls_r = create_tls_client_context(cli_cfg);
      if (!check(cli_tls_r.is_ok(), "create_tls_client_context().is_ok()"))
        return false;
      auto cli_tls = std::move(cli_tls_r.unwrap());

      std::optional<SocketServer> srv_opt;
      u16 port_used = 0;

      for (u16 delta = 0; delta < 48; ++delta)
      {
        const u16 port = static_cast<u16>(HTTPS_EPHEMERAL_BASE + delta);
        auto srv_r = create_socket_server(ctx, EProtocolType::TCP, port);
        if (srv_r.is_ok())
        {
          srv_opt = std::move(srv_r.unwrap());
          port_used = port;
          break;
        }
      }

      if (!check(srv_opt.has_value(), "srv_opt.has_value()"))
        return false;

      auto cli_r = create_socket_client(ctx, EProtocolType::TCP);
      if (!check(cli_r.is_ok(), "create_socket_client().is_ok()"))
        return false;
      auto cli = std::move(cli_r.unwrap());

      auto srv = std::move(*srv_opt);

      std::atomic<bool> server_ok{true};

      std::thread worker([&srv, &srv_tls, &server_ok, response]() {
        auto acc_r = tls_server_accept(srv, srv_tls);
        if (!acc_r.is_ok())
        {
          server_ok = false;
          return;
        }
        auto conn_s = std::move(acc_r.unwrap());

        auto req_r = connection_receive(conn_s, TLS_IO_CHUNK);
        if (!req_r.is_ok())
        {
          server_ok = false;
          return;
        }
        auto req = std::move(req_r.unwrap());
        if (!buffer_contains(Span<const u8>(req.data(), req.size()), "POST /ping"))
        {
          server_ok = false;
          return;
        }

        if (connection_send(conn_s, Span<const u8>(reinterpret_cast<const u8 *>(response.data()), response.size()))
                .is_err())
          server_ok = false;
      });

      auto conn_r = tls_client_connect(cli, String("127.0.0.1"), port_used, cli_tls);
      if (!check(conn_r.is_ok(), "tls_client_connect().is_ok()"))
        return false;
      auto conn_c = std::move(conn_r.unwrap());

      if (!check(connection_send(conn_c, Span<const u8>(reinterpret_cast<const u8 *>(request.data()), request.size()))
                         .is_ok(),
                 "connection_send(request).is_ok()"))
        return false;

      auto res_r = connection_receive(conn_c, TLS_IO_CHUNK);
      if (!check(res_r.is_ok(), "connection_receive(response).is_ok()"))
        return false;
      auto res = std::move(res_r.unwrap());
      if (!check(buffer_contains(Span<const u8>(res.data(), res.size()), "pong"), "response body is pong"))
        return false;

      worker.join();
      return check(server_ok.load(), "server_ok");
    }
  };

  const test::AutoRegister<TlsSuiteBlock> _registered_tls;
  const test::AutoRegister<HttpsSuiteBlock> _registered_https;
} // namespace
