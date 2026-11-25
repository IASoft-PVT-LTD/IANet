// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the Apache License, Version 2.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://www.apache.org/licenses/LICENSE-2.0>.

module;

#include <auxid/macros.hpp>

/**
 * @file ianet.tls.cppm
 * @brief Socket-oriented TLS support backed by the ianet.crypto provider.
 *
 * Provides server/client TLS contexts and connect/accept helpers that wrap
 * core @ref Connection handles with encrypted sessions.
 */

export module ianet.tls;

export import ianet;

export namespace ianet
{
  using namespace au;

  /** @brief Peer certificate verification policy for TLS clients. */
  enum class ETlsVerifyMode
  {
    None = 0,     ///< Do not verify the peer certificate.
    Required = 1, ///< Require a valid peer certificate signed by the configured CA.
  };

  /** @brief TLS configuration (PEM file paths). */
  struct TlsConfig
  {
    ETlsVerifyMode verify_mode = ETlsVerifyMode::Required; ///< Client/server verification mode.
    String cert_file;          ///< Path to PEM certificate (required for servers).
    String key_file;           ///< Path to PEM private key (required for servers).
    String ca_file;            ///< Path to PEM CA bundle (required for client verification).
    String expected_peer_name; ///< Client-side DNS/IP identity; defaults to the connection address.
    /// Client-side: also accept a single-label RFC 6125 wildcard subjectAltName
    /// (`*.example.com` for `api.example.com`) as public CAs issue. Off by default;
    /// private PKIs (IATunnel) keep exact matching. Never consults the Subject CN.
    bool allow_wildcard_peer_names = false;
  };

  /// @cond INTERNAL
  struct TlsContext_T
  {
    void *impl{};

    ~TlsContext_T();
  };

  /// @endcond

  /** @brief Opaque TLS context (server or client configuration). */
  using TlsContext = Box<TlsContext_T>;

  /**
   * @brief Creates a TLS server context.
   * @param config  Server certificate, key, and optional client CA for mutual TLS.
   */
  auto create_tls_server_context(const TlsConfig &config) -> Result<TlsContext>;

  /**
   * @brief Creates a TLS client context.
   * @param config  CA bundle and optional client certificate for mutual TLS.
   */
  auto create_tls_client_context(const TlsConfig &config) -> Result<TlsContext>;

  /**
   * @brief Connects to a remote host and performs the TLS handshake.
   * @param client   TCP client from @ref create_socket_client.
   * @param address  IPv4 address; also the peer identity unless overridden in @ref TlsConfig.
   * @param port     Remote port.
   * @param tls      Client TLS context from @ref create_tls_client_context.
   */
  auto tls_client_connect(SocketClient &client, const String &address, u16 port, TlsContext &tls) -> Result<Connection>;

  /**
   * @brief Accepts a TCP connection and performs the TLS handshake.
   * @param server  TCP server from @ref create_socket_server.
   * @param tls     Server TLS context from @ref create_tls_server_context.
   */
  auto tls_server_accept(SocketServer &server, TlsContext &tls) -> Result<Connection>;
} // namespace ianet

/// @cond INTERNAL
namespace ianet
{
  using namespace au;
  auto __tls_context_impl(TlsContext &tls) -> void *;
  auto __tls_context_is_server(TlsContext &tls) -> bool;
  auto __setup_tls_session(NativeSocket *sock, TlsContext &tls, const String &peer_name) -> Result<void *>;
} // namespace ianet

/// @endcond
