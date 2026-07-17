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

  struct TlsContextConfig
  {
    TlsRole role{};
    TlsCredentials credentials;
    TlsProfile profile;
    Vec<String> allowed_peer_names;
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
  [[nodiscard]] auto tls_write_step(TlsSession &session, Span<const u8> plaintext) -> Result<TlsIoResult>;
  [[nodiscard]] auto tls_read_step(TlsSession &session, Span<u8> plaintext) -> Result<TlsIoResult>;
  [[nodiscard]] auto tls_shutdown_step(TlsSession &session) -> Result<TlsShutdownState>;

  [[nodiscard]] auto pending_tls_ciphertext(const TlsSession &session) -> usize;
  [[nodiscard]] auto take_tls_ciphertext(TlsSession &session) -> Result<Vec<u8>>;
  [[nodiscard]] auto provide_tls_ciphertext(TlsSession &session, Span<const u8> ciphertext) -> Result<void>;
} // namespace ianet::crypto
