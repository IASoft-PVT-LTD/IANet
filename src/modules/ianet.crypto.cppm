// IANet: Cross-Platform Networking Library for C++

/**
 * @file ianet.crypto.cppm
 * @brief Provider-neutral, memory-BIO TLS primitives backed by AWS-LC.
 *
 * This API exposes cryptographic transport operations without exposing
 * AWS-LC headers or native handles. Callers own the network transport and
 * feed/drain TLS ciphertext explicitly.
 */

export module ianet.crypto;

export import ianet;

export namespace ianet::crypto
{
  using namespace au;

  inline constexpr usize MAX_TLS_ERROR_MESSAGE_SIZE = 1024U;
  inline constexpr usize MAX_TLS_CIPHERTEXT_CHUNK_SIZE = 64U * 1024U;
  inline constexpr usize MAX_TLS_BUFFERED_CIPHERTEXT_SIZE = 1024U * 1024U;

  enum class TlsRole
  {
    client,
    server,
  };

  /** @brief Peer-authentication policy applied by the TLS context. */
  enum class TlsPeerVerification
  {
    none,
    certificate,
    certificate_and_identity,
  };

  enum class TlsHandshakeState
  {
    needs_input,
    needs_output,
    complete,
  };

  enum class TlsIoState
  {
    complete,
    needs_input,
    needs_output,
    closed,
  };

  enum class TlsShutdownState
  {
    complete,
    needs_input,
    needs_output,
  };

  /** @brief Whether a local TLS 1.3 key update also asks the peer to update. */
  enum class TlsKeyUpdateRequest
  {
    local_only,
    request_peer,
  };

  struct TlsIoResult
  {
    TlsIoState state{};
    usize size{};
  };

  struct TlsCredentials
  {
    String certificate_file;
    String private_key_file;
    String trust_store_file;
  };

  /** @brief Exact TLS 1.3 group and cipher accepted by a context. */
  struct TlsProfile
  {
    String key_exchange_group;
    String cipher_suite;
  };

  /** @brief How a client matches the server certificate against the expected DNS name.
   *  `exact` accepts only an exact subjectAltName dNSName (the default; keep it for
   *  private PKIs such as IATunnel). `wildcard` additionally accepts a single-label
   *  RFC 6125 wildcard (`*.example.com` for `api.example.com`), which public CAs
   *  issue routinely; partial-label wildcards stay rejected and the Subject CN is
   *  never consulted in either mode. */
  enum class TlsIdentityMatching
  {
    exact,
    wildcard,
  };

  struct TlsContextConfig
  {
    TlsRole role{};
    TlsPeerVerification peer_verification{TlsPeerVerification::certificate_and_identity};
    TlsCredentials credentials;
    TlsProfile profile;
    Vec<String> allowed_peer_names;
    TlsIdentityMatching identity_matching{TlsIdentityMatching::exact};
  };

  struct TlsNegotiatedProfile
  {
    String protocol_version;
    String key_exchange_group;
    String cipher_suite;
    bool peer_verified{};
    bool session_reused{};
    bool early_data_accepted{};
  };

  /// @cond INTERNAL
  struct TlsContext_T
  {
    void *impl{};
    ~TlsContext_T();
  };

  struct TlsSession_T
  {
    void *impl{};
    ~TlsSession_T();
  };

  /// @endcond

  using TlsContext = Box<TlsContext_T>;
  using TlsSession = Box<TlsSession_T>;

  [[nodiscard]] auto create_tls_context(const TlsContextConfig &config) -> Result<TlsContext>;
  [[nodiscard]] auto create_tls_session(TlsContext &context, const String &expected_peer_name = {})
      -> Result<TlsSession>;

  [[nodiscard]] auto tls_handshake_step(TlsSession &session) -> Result<TlsHandshakeState>;
  [[nodiscard]] auto tls_negotiated_profile(TlsSession &session) -> Result<TlsNegotiatedProfile>;
  /** @brief Returns the configured peer identity that matched the authenticated certificate. */
  [[nodiscard]] auto tls_authenticated_peer_identity(const TlsSession &session) -> Result<String>;
  [[nodiscard]] auto tls_write_step(TlsSession &session, Span<const u8> plaintext) -> Result<TlsIoResult>;
  [[nodiscard]] auto tls_read_step(TlsSession &session, Span<u8> plaintext) -> Result<TlsIoResult>;
  [[nodiscard]] auto tls_shutdown_step(TlsSession &session) -> Result<TlsShutdownState>;
  [[nodiscard]] auto tls_key_update_step(TlsSession &session, TlsKeyUpdateRequest request) -> Result<void>;

  [[nodiscard]] auto pending_tls_ciphertext(const TlsSession &session) -> usize;
  [[nodiscard]] auto take_tls_ciphertext(TlsSession &session) -> Result<Vec<u8>>;
  [[nodiscard]] auto provide_tls_ciphertext(TlsSession &session, Span<const u8> ciphertext) -> Result<void>;

  // --- Inner-PSK defense-in-depth layer (iatunnel-v1-inner-psk profile) ------
  //
  // An authenticated-encryption layer applied to packets above a completed,
  // authenticated TLS session. Keys are derived once per connection from
  // HKDF-SHA-256(PSK, TLS-exporter) and are never static; see
  // docs/PROTOCOL.md "Inner-PSK defense-in-depth profile". These primitives
  // hold no sequence state — the caller supplies a per-direction sequence
  // number it owns and serializes.

  /** @brief Required pre-shared-key length in bytes (256-bit). */
  inline constexpr usize INNER_PSK_SIZE = 32U;

  /** @brief AEAD tag bytes added to each sealed message (ChaCha20-Poly1305). */
  inline constexpr usize INNER_SEAL_OVERHEAD_SIZE = 16U;

  /** @brief The direction an endpoint seals in; the other direction is opened. */
  enum class InnerDirection
  {
    client_to_server,
    server_to_client,
  };

  /// @cond INTERNAL
  struct InnerSealer_T
  {
    void *impl{};
    ~InnerSealer_T();
  };
  /// @endcond

  using InnerSealer = Box<InnerSealer_T>;

  /**
   * @brief Derives per-direction ChaCha20-Poly1305 keys from the TLS exporter
   *        and the PSK, returning a sealer bound to this connection.
   * @param session A session whose handshake has completed.
   * @param psk Exactly @ref INNER_PSK_SIZE bytes of high-entropy key material.
   * @param seal_direction The direction this endpoint sends (seals) in.
   * @return A sealer, or an error if the handshake is incomplete, the PSK size
   *         is wrong, or key derivation fails. PSK-derived material never
   *         leaves IANET and is wiped on sealer destruction.
   */
  [[nodiscard]] auto create_inner_sealer(TlsSession &session, Span<const u8> psk, InnerDirection seal_direction)
      -> Result<InnerSealer>;

  /**
   * @brief Seals plaintext with the send key at @p sequence.
   * @return Ciphertext||tag, of size `plaintext.size() + INNER_SEAL_OVERHEAD_SIZE`.
   */
  [[nodiscard]] auto inner_seal(InnerSealer &sealer, u64 sequence, Span<const u8> aad, Span<const u8> plaintext)
      -> Result<Vec<u8>>;

  /**
   * @brief Opens ciphertext||tag with the receive key at @p sequence.
   * @return The recovered plaintext, or a single fixed authentication error
   *         that distinguishes no failure cause and carries no secret data.
   */
  [[nodiscard]] auto inner_open(InnerSealer &sealer, u64 sequence, Span<const u8> aad, Span<const u8> sealed)
      -> Result<Vec<u8>>;

  /** @brief Guaranteed memory wipe (not elided by the optimizer). */
  auto secure_erase(Span<u8> bytes) -> void;
} // namespace ianet::crypto
