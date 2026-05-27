// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the PolyForm Noncommercial License 1.0.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://polyformproject.org/licenses/noncommercial/1.0.0>.

#include <auxid/macros.hpp>

#include <atomic>
#include <optional>
#include <thread>

#if AU_PLATFORM_WINDOWS
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

import ianet;
import auxid.test;

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

  struct IanetSuiteBlock final : test::Block
  {
    [[nodiscard]] auto get_name() const -> const char * override
    {
      return "ianet::suite";
    }

    auto declare_tests() -> void override
    {
      add_test("create_context", [this] { return create_context_(); });
      add_test("socket_client_connect_rejects_bad_ipv4_string",
               [this] { return socket_client_connect_rejects_bad_ipv4_string(); });
      add_test("tcp_echo_loopback", [this] { return tcp_echo_loopback(); });
      add_test("connection_receive_zero_returns_empty", [this] { return connection_receive_zero_returns_empty(); });
      add_test("udp_creation_and_accept_fails", [this] { return udp_creation_and_accept_fails(); });
      add_test("udp_client_send_receive", [this] { return udp_client_send_receive(); });
    }

    auto create_context_() -> bool
    {
      auto ctx_r = create_context();
      return check(ctx_r.is_ok(), "create_context().is_ok()");
    }

    auto socket_client_connect_rejects_bad_ipv4_string() -> bool
    {
      auto ctx_r = create_context();
      if (!check(ctx_r.is_ok(), "create_context().is_ok()"))
        return false;
      auto ctx = std::move(ctx_r.unwrap());

      auto cli_r = create_socket_client(ctx, EProtocolType::TCP);
      if (!check(cli_r.is_ok(), "create_socket_client().is_ok()"))
        return false;
      auto cli = std::move(cli_r.unwrap());

      auto bad = socket_client_connect(cli, String("not-a-valid-ipv4-address"), EPHEMERAL_BASE);
      return check(bad.is_err(), "socket_client_connect(bad address).is_err()");
    }

    auto tcp_echo_loopback() -> bool
    {
      auto ctx_r = create_context();
      if (!check(ctx_r.is_ok(), "create_context().is_ok()"))
        return false;
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

      if (!check(srv_opt.has_value(), "srv_opt.has_value()"))
        return false;

      auto cli_r = create_socket_client(ctx, EProtocolType::TCP);
      if (!check(cli_r.is_ok(), "create_socket_client().is_ok()"))
        return false;
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
      if (!check(conn_c_r.is_ok(), "socket_client_connect().is_ok()"))
        return false;
      auto conn_c = std::move(conn_c_r.unwrap());

      const u8 ping[] = {'p', 'i', 'n', 'g'};
      if (!check(connection_send(conn_c, Span<const u8>(ping, 4)).is_ok(), "connection_send(ping).is_ok()"))
        return false;

      auto reply_r = connection_receive(conn_c, 4);
      if (!check(reply_r.is_ok(), "connection_receive().is_ok()"))
        return false;
      auto reply = std::move(reply_r.unwrap());
      if (!check_eq(reply.size(), static_cast<usize>(4), "reply.size() == 4"))
        return false;

      const u8 pong[] = {'p', 'o', 'n', 'g'};
      if (!check(bytes_eq(Span<const u8>(reply.data(), reply.size()), Span<const u8>(pong, 4)), "reply is pong"))
        return false;

      worker.join();
      return check(server_ok.load(), "server_ok");
    }

    auto connection_receive_zero_returns_empty() -> bool
    {
      auto ctx_r = create_context();
      if (!check(ctx_r.is_ok(), "create_context().is_ok()"))
        return false;
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

      if (!check(srv_opt.has_value(), "srv_opt.has_value()"))
        return false;

      auto cli_r = create_socket_client(ctx, EProtocolType::TCP);
      if (!check(cli_r.is_ok(), "create_socket_client().is_ok()"))
        return false;
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
      if (!check(conn_c_r.is_ok(), "socket_client_connect().is_ok()"))
        return false;
      auto conn_c = std::move(conn_c_r.unwrap());

      auto empty_r = connection_receive(conn_c, 0);
      if (!check(empty_r.is_ok(), "connection_receive(0).is_ok()"))
        return false;
      if (!check(empty_r.unwrap().empty(), "connection_receive(0) is empty"))
        return false;

      worker.join();
      return true;
    }

    auto udp_creation_and_accept_fails() -> bool
    {
      auto ctx_r = create_context();
      if (!check(ctx_r.is_ok(), "create_context().is_ok()"))
        return false;
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

      if (!check(srv_opt.has_value(), "srv_opt.has_value()"))
        return false;
      auto srv = std::move(*srv_opt);

      auto acc_r = socket_server_accept(srv);
      if (!check(acc_r.is_err(), "socket_server_accept(UDP).is_err()"))
        return false;

      auto cli_r = create_socket_client(ctx, EProtocolType::UDP);
      if (!check(cli_r.is_ok(), "create_socket_client(UDP).is_ok()"))
        return false;
      auto cli = std::move(cli_r.unwrap());

      auto conn_c_r = socket_client_connect(cli, String("127.0.0.1"), port_used);
      return check(conn_c_r.is_ok(), "socket_client_connect(UDP).is_ok()");
    }

    auto udp_client_send_receive() -> bool
    {
      auto ctx_r = create_context();
      if (!check(ctx_r.is_ok(), "create_context().is_ok()"))
        return false;
      auto ctx = std::move(ctx_r.unwrap());

#if AU_PLATFORM_WINDOWS
      SOCKET srv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      if (!check(srv_sock != INVALID_SOCKET, "server socket valid"))
        return false;
#else
      int srv_sock = socket(AF_INET, SOCK_DGRAM, 0);
      if (!check(srv_sock >= 0, "server socket valid"))
        return false;
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
      if (!check(port_used != 0, "port_used != 0"))
        return false;

      auto cli_r = create_socket_client(ctx, EProtocolType::UDP);
      if (!check(cli_r.is_ok(), "create_socket_client(UDP).is_ok()"))
        return false;
      auto cli = std::move(cli_r.unwrap());

      auto conn_c_r = socket_client_connect(cli, String("127.0.0.1"), port_used);
      if (!check(conn_c_r.is_ok(), "socket_client_connect().is_ok()"))
        return false;
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
      if (!check(connection_send(conn_c, Span<const u8>(ping, 4)).is_ok(), "connection_send(ping).is_ok()"))
        return false;

      auto reply_r = connection_receive(conn_c, 4);
      if (!check(reply_r.is_ok(), "connection_receive().is_ok()"))
        return false;
      auto reply = std::move(reply_r.unwrap());
      if (!check_eq(reply.size(), static_cast<usize>(4), "reply.size() == 4"))
        return false;

      const u8 pong[] = {'p', 'o', 'n', 'g'};
      if (!check(bytes_eq(Span<const u8>(reply.data(), reply.size()), Span<const u8>(pong, 4)), "reply is pong"))
        return false;

      worker.join();
      if (!check(server_ok.load(), "server_ok"))
        return false;

#if AU_PLATFORM_WINDOWS
      closesocket(srv_sock);
#else
      ::close(srv_sock);
#endif

      return true;
    }
  };

  const test::AutoRegister<IanetSuiteBlock> _registered;
} // namespace
