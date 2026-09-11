// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the PolyForm Noncommercial License 1.0.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://polyformproject.org/licenses/noncommercial/1.0.0>.

// Regression tests for the TLS key-exchange group negotiation fix (K6a).
//
// The socket TLS contexts default to offering "X25519MLKEM768:X25519:P-256"
// so that the post-quantum hybrid group stays preferred but the handshake
// still succeeds against peers that only support a classical group (e.g.
// OpenSSL 3.0.x nginx, which rejects an MLKEM-only ClientHello with
// "no suitable key share"). These tests drive an in-memory TLS 1.3 handshake
// between a client context offering the full list and a server context
// restricted to a single classical group, and assert the handshake completes
// and negotiates that exact group.

#include <string>

import ianet.crypto;
import auxid.test;

using namespace au;
using namespace ianet;

namespace
{
  constexpr const char *CLIENT_GROUPS = "X25519MLKEM768:X25519:P-256";
  constexpr const char *CIPHER = "TLS_CHACHA20_POLY1305_SHA256";
  constexpr usize MAX_HANDSHAKE_STEPS = 512U;

  auto make_context(crypto::TlsRole role, const char *groups) -> Result<crypto::TlsContext>
  {
    crypto::TlsContextConfig config;
    config.role = role;
    config.peer_verification = crypto::TlsPeerVerification::none;
    config.profile = crypto::TlsProfile{
        .key_exchange_group = String(groups),
        .cipher_suite = String(CIPHER),
    };
    if (role == crypto::TlsRole::server)
    {
      config.credentials.certificate_file = String("tests/fixtures/server.crt");
      config.credentials.private_key_file = String("tests/fixtures/server.key");
    }
    return crypto::create_tls_context(config);
  }

  // Copy every pending ciphertext record from `from` into `to`. Returns false on
  // any transport error.
  auto shuttle(crypto::TlsSession &from, crypto::TlsSession &to) -> bool
  {
    while (crypto::pending_tls_ciphertext(from) != 0U)
    {
      auto record = crypto::take_tls_ciphertext(from);
      if (record.is_err())
        return false;
      auto bytes = std::move(record.unwrap());
      if (crypto::provide_tls_ciphertext(to, Span<const u8>(bytes.data(), bytes.size())).is_err())
        return false;
    }
    return true;
  }

  // Drive both sessions to a completed TLS 1.3 handshake entirely in memory.
  auto drive_handshake(crypto::TlsSession &client, crypto::TlsSession &server, test::Block &block) -> bool
  {
    bool client_done = false;
    bool server_done = false;
    for (usize step = 0U; step < MAX_HANDSHAKE_STEPS && !(client_done && server_done); ++step)
    {
      auto client_state = crypto::tls_handshake_step(client);
      if (!block.check(client_state.is_ok(), "client tls_handshake_step().is_ok()"))
        return false;
      if (client_state.unwrap() == crypto::TlsHandshakeState::complete)
        client_done = true;
      if (!block.check(shuttle(client, server), "client->server ciphertext shuttle"))
        return false;

      auto server_state = crypto::tls_handshake_step(server);
      if (!block.check(server_state.is_ok(), "server tls_handshake_step().is_ok()"))
        return false;
      if (server_state.unwrap() == crypto::TlsHandshakeState::complete)
        server_done = true;
      if (!block.check(shuttle(server, client), "server->client ciphertext shuttle"))
        return false;
    }
    return block.check(client_done && server_done, "handshake completed on both peers");
  }

  auto negotiate_with_restricted_server(const char *server_group, const char *expected_group, test::Block &block)
      -> bool
  {
    auto client_ctx_r = make_context(crypto::TlsRole::client, CLIENT_GROUPS);
    if (!block.check(client_ctx_r.is_ok(), "create client context (full group list)"))
      return false;
    auto client_ctx = std::move(client_ctx_r.unwrap());

    auto server_ctx_r = make_context(crypto::TlsRole::server, server_group);
    if (!block.check(server_ctx_r.is_ok(), "create server context (restricted group)"))
      return false;
    auto server_ctx = std::move(server_ctx_r.unwrap());

    auto client_r = crypto::create_tls_session(client_ctx, String("localhost"));
    if (!block.check(client_r.is_ok(), "create_tls_session(client)"))
      return false;
    auto client = std::move(client_r.unwrap());

    auto server_r = crypto::create_tls_session(server_ctx);
    if (!block.check(server_r.is_ok(), "create_tls_session(server)"))
      return false;
    auto server = std::move(server_r.unwrap());

    if (!drive_handshake(client, server, block))
      return false;

    auto profile_r = crypto::tls_negotiated_profile(client);
    if (!block.check(profile_r.is_ok(), "tls_negotiated_profile(client)"))
      return false;
    const crypto::TlsNegotiatedProfile profile = std::move(profile_r.unwrap());
    return block.check_eq(std::string(profile.key_exchange_group.data(), profile.key_exchange_group.size()),
                          std::string(expected_group), "negotiated key-exchange group");
  }

  struct TlsGroupSuiteBlock final : test::Block
  {
    [[nodiscard]] auto get_name() const -> const char * override
    {
      return "ianet::tls_group_suite";
    }

    auto declare_tests() -> void override
    {
      add_test("negotiates_x25519_with_classical_server",
               [this] { return negotiate_with_restricted_server("X25519", "X25519", *this); });
      add_test("negotiates_p256_with_classical_server",
               [this] { return negotiate_with_restricted_server("P-256", "P-256", *this); });
    }
  };

  const test::AutoRegister<TlsGroupSuiteBlock> _registered_tls_groups;
} // namespace
