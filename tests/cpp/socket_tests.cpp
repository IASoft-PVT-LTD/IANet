// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the PolyForm Noncommercial License 1.0.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://polyformproject.org/licenses/noncommercial/1.0.0>.

#include <ianet/ianet.hpp>

#include <auxid/utils/test.hpp>

#include <atomic>
#include <thread>

#if AU_PLATFORM_WINDOWS
#  define NOMINMAX
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

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

auto test_socket_client_connect_rejects_bad_ipv4_string() -> bool
{
  auto ctx_r = create_context();
  AUT_CHECK(ctx_r.is_ok());
  auto ctx = std::move(ctx_r.unwrap());

  auto cli_r = create_socket_client(ctx, EProtocolType::TCP);
  AUT_CHECK(cli_r.is_ok());
  auto cli = std::move(cli_r.unwrap());

  auto bad = socket_client_connect(cli, String("not-a-valid-ipv4-address"), EPHEMERAL_BASE);
  AUT_CHECK(bad.is_err());

  return true;
}

auto test_tcp_echo_loopback() -> bool
{
  auto ctx_r = create_context();
  AUT_CHECK(ctx_r.is_ok());
  auto ctx = std::move(ctx_r.unwrap());

  std::optional<SocketServer> srv_opt;
  u16 port_used = 0;

  for (u16 delta = 0; delta < 48; ++delta)
  {
    const u16 port = static_cast<u16>(EPHEMERAL_BASE + delta);
    auto srv_r = create_socket_server(ctx, EProtocolType::TCP, port);
    if (srv_r.is_ok())
    {
      srv_opt = std::move(srv_r.unwrap());
      port_used = port;
      break;
    }
  }

  AUT_CHECK(srv_opt.has_value());

  auto cli_r = create_socket_client(ctx, EProtocolType::TCP);
  AUT_CHECK(cli_r.is_ok());
  auto cli = std::move(cli_r.unwrap());

  auto srv = std::move(*srv_opt);

  std::atomic<bool> server_ok{true};

  std::thread worker([&srv, &server_ok]() {
    auto acc_r = socket_server_accept(srv);
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

  auto conn_c_r = socket_client_connect(cli, String("127.0.0.1"), port_used);
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

  std::optional<SocketServer> srv_opt;
  u16 port_used = 0;

  for (u16 delta = 0; delta < 48; ++delta)
  {
    const u16 port = static_cast<u16>(EPHEMERAL_BASE + 64 + delta);
    auto srv_r = create_socket_server(ctx, EProtocolType::TCP, port);
    if (srv_r.is_ok())
    {
      srv_opt = std::move(srv_r.unwrap());
      port_used = port;
      break;
    }
  }

  AUT_CHECK(srv_opt.has_value());

  auto cli_r = create_socket_client(ctx, EProtocolType::TCP);
  AUT_CHECK(cli_r.is_ok());
  auto cli = std::move(cli_r.unwrap());

  auto srv = std::move(*srv_opt);

  std::thread worker([&srv]() {
    auto acc_r = socket_server_accept(srv);
    if (!acc_r.is_ok())
      return;
    auto conn_s = std::move(acc_r.unwrap());
    (void) connection_receive(conn_s, 0);
  });

  auto conn_c_r = socket_client_connect(cli, String("127.0.0.1"), port_used);
  AUT_CHECK(conn_c_r.is_ok());
  auto conn_c = std::move(conn_c_r.unwrap());

  auto empty_r = connection_receive(conn_c, 0);
  AUT_CHECK(empty_r.is_ok());
  AUT_CHECK(empty_r.unwrap().empty());

  worker.join();

  return true;
}

auto test_udp_creation_and_accept_fails() -> bool
{
  auto ctx_r = create_context();
  AUT_CHECK(ctx_r.is_ok());
  auto ctx = std::move(ctx_r.unwrap());

  std::optional<SocketServer> srv_opt;
  u16 port_used = 0;

  for (u16 delta = 0; delta < 48; ++delta)
  {
    const u16 port = static_cast<u16>(EPHEMERAL_BASE + 128 + delta);
    auto srv_r = create_socket_server(ctx, EProtocolType::UDP, port);
    if (srv_r.is_ok())
    {
      srv_opt = std::move(srv_r.unwrap());
      port_used = port;
      break;
    }
  }

  AUT_CHECK(srv_opt.has_value());
  auto srv = std::move(*srv_opt);

  // Accept should fail for UDP
  auto acc_r = socket_server_accept(srv);
  AUT_CHECK(acc_r.is_err());

  auto cli_r = create_socket_client(ctx, EProtocolType::UDP);
  AUT_CHECK(cli_r.is_ok());
  auto cli = std::move(cli_r.unwrap());

  // Connect should succeed for UDP (sets default destination)
  auto conn_c_r = socket_client_connect(cli, String("127.0.0.1"), port_used);
  AUT_CHECK(conn_c_r.is_ok());

  return true;
}

auto test_udp_client_send_receive() -> bool
{
  auto ctx_r = create_context();
  AUT_CHECK(ctx_r.is_ok());
  auto ctx = std::move(ctx_r.unwrap());

  // Create a native UDP socket to act as the server
#if AU_PLATFORM_WINDOWS
  SOCKET srv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  AUT_CHECK(srv_sock != INVALID_SOCKET);
#else
  int srv_sock = socket(AF_INET, SOCK_DGRAM, 0);
  AUT_CHECK(srv_sock >= 0);
#endif

  sockaddr_in srv_addr{};
  srv_addr.sin_family = AF_INET;
  srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  u16 port_used = 0;
  for (u16 delta = 0; delta < 48; ++delta)
  {
    const u16 port = static_cast<u16>(EPHEMERAL_BASE + 256 + delta);
    srv_addr.sin_port = htons(port);
#if AU_PLATFORM_WINDOWS
    if (bind(srv_sock, reinterpret_cast<sockaddr *>(&srv_addr), sizeof(srv_addr)) != SOCKET_ERROR)
#else
    if (::bind(srv_sock, reinterpret_cast<sockaddr *>(&srv_addr), sizeof(srv_addr)) == 0)
#endif
    {
      port_used = port;
      break;
    }
  }
  AUT_CHECK(port_used != 0);

  auto cli_r = create_socket_client(ctx, EProtocolType::UDP);
  AUT_CHECK(cli_r.is_ok());
  auto cli = std::move(cli_r.unwrap());

  auto conn_c_r = socket_client_connect(cli, String("127.0.0.1"), port_used);
  AUT_CHECK(conn_c_r.is_ok());
  auto conn_c = std::move(conn_c_r.unwrap());

  std::atomic<bool> server_ok{true};
  std::thread worker([srv_sock, &server_ok]() {
    char buf[16];
    sockaddr_in cli_addr{};
    socklen_t cli_len = sizeof(cli_addr);
#if AU_PLATFORM_WINDOWS
    int n = recvfrom(srv_sock, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&cli_addr), &cli_len);
#else
    int n = recvfrom(srv_sock, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&cli_addr), &cli_len);
#endif
    if (n != 4)
    {
      server_ok = false;
      return;
    }
    if (buf[0] != 'p' || buf[1] != 'i' || buf[2] != 'n' || buf[3] != 'g')
    {
      server_ok = false;
      return;
    }

    const char pong[] = {'p', 'o', 'n', 'g'};
#if AU_PLATFORM_WINDOWS
    if (sendto(srv_sock, pong, 4, 0, reinterpret_cast<sockaddr *>(&cli_addr), cli_len) != 4)
#else
    if (sendto(srv_sock, pong, 4, 0, reinterpret_cast<sockaddr *>(&cli_addr), cli_len) != 4)
#endif
      server_ok = false;
  });

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

#if AU_PLATFORM_WINDOWS
  closesocket(srv_sock);
#else
  ::close(srv_sock);
#endif

  return true;
}

AUT_BEGIN_TEST_LIST()
AUT_ADD_TEST(test_create_context);
AUT_ADD_TEST(test_socket_client_connect_rejects_bad_ipv4_string);
AUT_ADD_TEST(test_tcp_echo_loopback);
AUT_ADD_TEST(test_connection_receive_zero_returns_empty);
AUT_ADD_TEST(test_udp_creation_and_accept_fails);
AUT_ADD_TEST(test_udp_client_send_receive);
AUT_END_TEST_LIST()

AUT_END_BLOCK()

AUT_REGISTER_ENTRY(ianet, suite);
