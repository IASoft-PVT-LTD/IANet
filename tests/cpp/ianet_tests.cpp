// IANet: Cross-Platform Networking Library for C++
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#include <ianet/ianet.hpp>

#include <auxid/utils/test.hpp>

#include <atomic>
#include <thread>

using namespace au;
using namespace ianet;

namespace
{
  constexpr u16 EPHEMERAL_BASE = 38120;

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
} // namespace

AUT_BEGIN_BLOCK(ianet, suite)

auto test_create_context() -> bool
{
  auto ctx_r = create_context();
  AUT_CHECK(ctx_r.is_ok());
  return true;
}

auto test_client_connect_rejects_bad_ipv4_string() -> bool
{
  auto ctx_r = create_context();
  AUT_CHECK(ctx_r.is_ok());
  auto ctx = std::move(ctx_r.unwrap());

  auto cli_r = create_client(ctx);
  AUT_CHECK(cli_r.is_ok());
  auto cli = std::move(cli_r.unwrap());

  auto bad = client_connect(cli, String("not-a-valid-ipv4-address"), EPHEMERAL_BASE);
  AUT_CHECK(bad.is_err());

  return true;
}

auto test_tcp_echo_loopback() -> bool
{
  auto ctx_r = create_context();
  AUT_CHECK(ctx_r.is_ok());
  auto ctx = std::move(ctx_r.unwrap());

  std::optional<Server> srv_opt;
  u16 port_used = 0;

  for (u16 delta = 0; delta < 48; ++delta)
  {
    const u16 port = static_cast<u16>(EPHEMERAL_BASE + delta);
    auto srv_r = create_server(ctx, port);
    if (srv_r.is_ok())
    {
      srv_opt = std::move(srv_r.unwrap());
      port_used = port;
      break;
    }
  }

  AUT_CHECK(srv_opt.has_value());

  auto cli_r = create_client(ctx);
  AUT_CHECK(cli_r.is_ok());
  auto cli = std::move(cli_r.unwrap());

  auto srv = std::move(*srv_opt);

  std::atomic<bool> server_ok{true};

  std::thread worker([&srv, &server_ok]() {
    auto acc_r = server_accept(srv);
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

  auto conn_c_r = client_connect(cli, String("127.0.0.1"), port_used);
  AUT_CHECK(conn_c_r.is_ok());
  auto conn_c = std::move(conn_c_r.unwrap());

  const u8 ping[] = {'p', 'i', 'n', 'g'};
  AUT_CHECK(connection_send(conn_c, Span<const u8>(ping, 4)).is_ok());

  auto reply_r = connection_receive(conn_c, 4);
  AUT_CHECK(reply_r.is_ok());
  auto reply = std::move(reply_r.unwrap());
  AUT_CHECK_EQ(reply.size(), static_cast<usize>(4));

  const u8 pong[] = {'p', 'o', 'n', 'g'};
  AUT_CHECK(bytes_eq(Span<const u8>(reply.data(), reply.size()), Span<const u8>(pong, 4)));

  worker.join();
  AUT_CHECK(server_ok.load());

  return true;
}

auto test_connection_receive_zero_returns_empty() -> bool
{
  auto ctx_r = create_context();
  AUT_CHECK(ctx_r.is_ok());
  auto ctx = std::move(ctx_r.unwrap());

  std::optional<Server> srv_opt;
  u16 port_used = 0;

  for (u16 delta = 0; delta < 48; ++delta)
  {
    const u16 port = static_cast<u16>(EPHEMERAL_BASE + 64 + delta);
    auto srv_r = create_server(ctx, port);
    if (srv_r.is_ok())
    {
      srv_opt = std::move(srv_r.unwrap());
      port_used = port;
      break;
    }
  }

  AUT_CHECK(srv_opt.has_value());

  auto cli_r = create_client(ctx);
  AUT_CHECK(cli_r.is_ok());
  auto cli = std::move(cli_r.unwrap());

  auto srv = std::move(*srv_opt);

  std::thread worker([&srv]() {
    auto acc_r = server_accept(srv);
    if (!acc_r.is_ok())
      return;
    auto conn_s = std::move(acc_r.unwrap());
    (void) connection_receive(conn_s, 0);
  });

  auto conn_c_r = client_connect(cli, String("127.0.0.1"), port_used);
  AUT_CHECK(conn_c_r.is_ok());
  auto conn_c = std::move(conn_c_r.unwrap());

  auto empty_r = connection_receive(conn_c, 0);
  AUT_CHECK(empty_r.is_ok());
  AUT_CHECK(empty_r.unwrap().empty());

  worker.join();

  return true;
}

AUT_BEGIN_TEST_LIST()
AUT_ADD_TEST(test_create_context);
AUT_ADD_TEST(test_client_connect_rejects_bad_ipv4_string);
AUT_ADD_TEST(test_tcp_echo_loopback);
AUT_ADD_TEST(test_connection_receive_zero_returns_empty);
AUT_END_TEST_LIST()

AUT_END_BLOCK()

AUT_REGISTER_ENTRY(ianet, suite);
