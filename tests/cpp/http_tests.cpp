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

using namespace au;
using namespace ianet;

namespace
{
  constexpr u16 HTTP_EPHEMERAL_BASE = 39120;

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

AUT_BEGIN_BLOCK(ianet, http_suite)

auto test_http_ping_pong() -> bool
{
  auto ctx_r = create_context();
  AUT_CHECK(ctx_r.is_ok());
  auto ctx = std::move(ctx_r.unwrap());

  std::optional<HttpServer> srv_opt;
  u16 port_used = 0;

  for (u16 delta = 0; delta < 48; ++delta)
  {
    const u16 port = static_cast<u16>(HTTP_EPHEMERAL_BASE + delta);
    auto srv_r = create_http_server(ctx, port);
    if (srv_r.is_ok())
    {
      srv_opt = std::move(srv_r.unwrap());
      port_used = port;
      break;
    }
  }

  AUT_CHECK(srv_opt.has_value());

  auto cli_r = create_http_client(ctx);
  AUT_CHECK(cli_r.is_ok());
  auto cli = std::move(cli_r.unwrap());

  auto srv = std::move(*srv_opt);

  std::atomic<bool> server_ok{true};

  std::thread worker([&srv, &server_ok]() {
    auto acc_r = http_server_accept(srv);
    if (!acc_r.is_ok())
    {
      server_ok = false;
      return;
    }
    auto conn_s = std::move(acc_r.unwrap());

    auto req_r = http_connection_receive_request(conn_s);
    if (!req_r.is_ok())
    {
      server_ok = false;
      return;
    }
    auto req = std::move(req_r.unwrap());

    if (req.method != "POST" || req.path != "/ping" || req.minor_version != 1)
    {
      server_ok = false;
      return;
    }

    const u8 expected_body[] = {'p', 'i', 'n', 'g'};
    if (!bytes_eq(Span<const u8>(req.body.data(), req.body.size()), Span<const u8>(expected_body, 4)))
    {
      server_ok = false;
      return;
    }

    HttpResponse res;
    res.minor_version = 1;
    res.status_code = 200;
    res.status_message = "OK";
    res.headers.push_back(Pair<String, String>("Content-Type", "text/plain"));

    const u8 pong_body[] = {'p', 'o', 'n', 'g'};
    for (auto b : pong_body)
      res.body.push_back(b);

    if (http_connection_send_response(conn_s, res).is_err())
      server_ok = false;
  });

  auto conn_c_r = http_client_connect(cli, String("127.0.0.1"), port_used);
  AUT_CHECK(conn_c_r.is_ok());
  auto conn_c = std::move(conn_c_r.unwrap());

  HttpRequest req;
  req.method = "POST";
  req.path = "/ping";
  req.minor_version = 1;
  req.headers.push_back(Pair<String, String>("Content-Type", "text/plain"));

  const u8 ping_body[] = {'p', 'i', 'n', 'g'};
  for (auto b : ping_body)
    req.body.push_back(b);

  AUT_CHECK(http_connection_send_request(conn_c, req).is_ok());

  auto res_r = http_connection_receive_response(conn_c);
  AUT_CHECK(res_r.is_ok());
  auto res = std::move(res_r.unwrap());

  AUT_CHECK_EQ(res.status_code, static_cast<u16>(200));
  AUT_CHECK(res.status_message == "OK");
  AUT_CHECK_EQ(res.body.size(), static_cast<usize>(4));

  const u8 expected_pong[] = {'p', 'o', 'n', 'g'};
  AUT_CHECK(bytes_eq(Span<const u8>(res.body.data(), res.body.size()), Span<const u8>(expected_pong, 4)));

  worker.join();
  AUT_CHECK(server_ok.load());

  return true;
}

AUT_BEGIN_TEST_LIST()
AUT_ADD_TEST(test_http_ping_pong);
AUT_END_TEST_LIST()

AUT_END_BLOCK()

AUT_REGISTER_ENTRY(ianet, http_suite);
