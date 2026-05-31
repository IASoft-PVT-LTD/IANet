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

export module ianet.tls;

export import ianet;

export namespace ianet
{
  using namespace au;

  enum class ETlsVerifyMode
  {
    None = 0,
    Required = 1,
  };

  struct TlsConfig
  {
    ETlsVerifyMode verify_mode = ETlsVerifyMode::Required;
    String cert_file;
    String key_file;
    String ca_file;
  };

  struct TlsContext_T
  {
    void *impl{};

    ~TlsContext_T();
  };

  using TlsContext = Box<TlsContext_T>;

  auto create_tls_server_context(const TlsConfig &config) -> Result<TlsContext>;
  auto create_tls_client_context(const TlsConfig &config) -> Result<TlsContext>;

  auto tls_client_connect(SocketClient &client, const String &address, u16 port, TlsContext &tls) -> Result<Connection>;
  auto tls_server_accept(SocketServer &server, TlsContext &tls) -> Result<Connection>;
} // namespace ianet

namespace ianet
{
  using namespace au;
  auto __tls_context_impl(TlsContext &tls) -> void *;
  auto __tls_context_is_server(TlsContext &tls) -> bool;
  auto __setup_tls_session(NativeSocket *sock, TlsContext &tls, const char *hostname) -> Result<void *>;
} // namespace ianet
