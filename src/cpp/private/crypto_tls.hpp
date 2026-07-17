#pragma once

#include <openssl/ssl.h>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
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
    Credentials credentials;
    Profile profile;
    std::vector<std::string> allowed_peer_names;
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
  template<typename T> using Result = std::expected<T, std::string>;

  struct Context
  {
    SslContextPtr native;
    Role role{};
    Profile profile;
    std::vector<std::string> allowed_peer_names;
  };

  struct Session
  {
    SslPtr native;
    BIO *inbound{};
    BIO *outbound{};
    Role role{};
    Profile profile;
    std::vector<std::string> expected_peer_names;
    bool authenticated{};
  };

  auto clear_errors() noexcept -> void;
  [[nodiscard]] auto format_error(std::string_view operation) -> std::string;
  [[nodiscard]] auto create_context(const ContextConfig &config) -> Result<Context>;
  [[nodiscard]] auto create_session(Context &context, std::string_view expected_peer_name = {}) -> Result<Session>;
  [[nodiscard]] auto handshake_step(Session &session) -> Result<HandshakeState>;
  [[nodiscard]] auto validate_profile(const Session &session) -> Result<void>;
  [[nodiscard]] auto write_step(Session &session, std::span<const std::uint8_t> plaintext) -> Result<IoResult>;
  [[nodiscard]] auto read_step(Session &session, std::span<std::uint8_t> plaintext) -> Result<IoResult>;
  [[nodiscard]] auto shutdown_step(Session &session) -> Result<ShutdownState>;
  [[nodiscard]] auto pending_ciphertext(const Session &session) noexcept -> std::size_t;
  [[nodiscard]] auto take_ciphertext(Session &session) -> Result<std::vector<std::uint8_t>>;
  [[nodiscard]] auto provide_ciphertext(Session &session, std::span<const std::uint8_t> ciphertext) -> Result<void>;
} // namespace ianet::crypto::detail
