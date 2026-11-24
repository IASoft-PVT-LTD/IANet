#pragma once

#include <openssl/ssl.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace ianet::crypto::detail
{
  inline constexpr std::size_t MAX_ERROR_MESSAGE_SIZE = 1024U;
  inline constexpr std::size_t MAX_CIPHERTEXT_CHUNK_SIZE = 64U * 1024U;
  inline constexpr std::size_t MAX_BUFFERED_CIPHERTEXT_SIZE = 1024U * 1024U;

  enum class Role
  {
    client,
    server,
  };

  enum class PeerVerification
  {
    none,
    certificate,
    certificate_and_identity,
  };

  // How a client matches the server certificate against the expected DNS name.
  // `exact` (default, IATunnel) accepts only an exact subjectAltName dNSName;
  // `wildcard` also accepts a single-label RFC 6125 wildcard (`*.example.com`
  // matches `api.example.com`, never `a.b.example.com`, never partial labels).
  // The Subject CN is never consulted in either mode.
  enum class IdentityMatching
  {
    exact,
    wildcard,
  };

  enum class HandshakeState
  {
    needs_input,
    needs_output,
    complete,
  };

  enum class IoState
  {
    complete,
    needs_input,
    needs_output,
    closed,
  };

  enum class ShutdownState
  {
    complete,
    needs_input,
    needs_output,
  };

  struct IoResult
  {
    IoState state{};
    std::size_t size{};
  };

  struct Credentials
  {
    std::string certificate_file;
    std::string private_key_file;
    std::string trust_store_file;
  };

  struct Profile
  {
    std::string key_exchange_group;
    std::string cipher_suite;
  };

  struct ContextConfig
  {
    Role role{};
    PeerVerification peer_verification{PeerVerification::certificate_and_identity};
    Credentials credentials;
    Profile profile;
    std::vector<std::string> allowed_peer_names;
    IdentityMatching identity_matching{IdentityMatching::exact};
  };

  struct SslContextDeleter
  {
    auto operator()(SSL_CTX *context) const noexcept -> void;
  };

  struct SslDeleter
  {
    auto operator()(SSL *session) const noexcept -> void;
  };

  struct BioDeleter
  {
    auto operator()(BIO *bio) const noexcept -> void;
  };

  struct X509Deleter
  {
    auto operator()(X509 *certificate) const noexcept -> void;
  };

  using SslContextPtr = std::unique_ptr<SSL_CTX, SslContextDeleter>;
  using SslPtr = std::unique_ptr<SSL, SslDeleter>;
  using BioPtr = std::unique_ptr<BIO, BioDeleter>;
  using X509Ptr = std::unique_ptr<X509, X509Deleter>;

  struct Failure
  {
    std::string message;
  };

  // The part of std::expected (C++23) that the TLS code needs. Auxid's Result is not
  // available here: this header is included in global module fragments.
  template<typename T> class Result
  {
public:
    Result(T value) : m_state(std::in_place_index<0>, std::move(value))
    {
    }

    Result(Failure failure) : m_state(std::in_place_index<1>, std::move(failure.message))
    {
    }

    explicit operator bool() const noexcept
    {
      return m_state.index() == 0U;
    }

    auto value() noexcept -> T &
    {
      return *std::get_if<0>(&m_state);
    }

    auto operator->() noexcept -> T *
    {
      return std::get_if<0>(&m_state);
    }

    auto error() noexcept -> std::string &
    {
      return *std::get_if<1>(&m_state);
    }

private:
    std::variant<T, std::string> m_state;
  };

  template<> class Result<void>
  {
public:
    Result() = default;

    Result(Failure failure) : m_error(std::move(failure.message)), m_failed(true)
    {
    }

    explicit operator bool() const noexcept
    {
      return !m_failed;
    }

    auto error() noexcept -> std::string &
    {
      return m_error;
    }

private:
    std::string m_error;
    bool m_failed{};
  };

  struct Context
  {
    SslContextPtr native;
    Role role{};
    PeerVerification peer_verification{PeerVerification::certificate_and_identity};
    Profile profile;
    std::vector<std::string> allowed_peer_names;
    IdentityMatching identity_matching{IdentityMatching::exact};
  };

  struct Session
  {
    SslPtr native;
    BIO *inbound{};
    BIO *outbound{};
    Role role{};
    PeerVerification peer_verification{PeerVerification::certificate_and_identity};
    Profile profile;
    std::vector<std::string> expected_peer_names;
    std::string authenticated_peer_identity;
    bool authenticated{};
    IdentityMatching identity_matching{IdentityMatching::exact};
  };

  auto clear_errors() noexcept -> void;
  [[nodiscard]] auto format_error(std::string_view operation) -> std::string;
  [[nodiscard]] auto create_context(const ContextConfig &config) -> Result<Context>;
  [[nodiscard]] auto create_session(Context &context, std::string_view expected_peer_name = {}) -> Result<Session>;
  [[nodiscard]] auto handshake_step(Session &session) -> Result<HandshakeState>;
  [[nodiscard]] auto validate_profile(Session &session) -> Result<void>;
  [[nodiscard]] auto write_step(Session &session, std::span<const std::uint8_t> plaintext) -> Result<IoResult>;
  [[nodiscard]] auto read_step(Session &session, std::span<std::uint8_t> plaintext) -> Result<IoResult>;
  [[nodiscard]] auto shutdown_step(Session &session) -> Result<ShutdownState>;
  [[nodiscard]] auto key_update_step(Session &session, bool request_peer) -> Result<void>;
  [[nodiscard]] auto pending_ciphertext(const Session &session) noexcept -> std::size_t;
  [[nodiscard]] auto take_ciphertext(Session &session) -> Result<std::vector<std::uint8_t>>;
  [[nodiscard]] auto provide_ciphertext(Session &session, std::span<const std::uint8_t> ciphertext) -> Result<void>;
} // namespace ianet::crypto::detail
