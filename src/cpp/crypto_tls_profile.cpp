#include "private/crypto_tls.hpp"

#include <openssl/err.h>

#include <algorithm>

namespace ianet::crypto::detail
{
  namespace
  {
    constexpr std::size_t MAX_ERROR_ENTRIES = 4U;
    constexpr std::size_t ERROR_ENTRY_BUFFER_SIZE = 256U;
    constexpr int MAX_CERTIFICATE_CHAIN_DEPTH = 4;

    auto contains_nul(std::string_view value) -> bool
    {
      return value.find('\0') != std::string_view::npos;
    }

    auto valid_text(std::string_view value) -> bool
    {
      return !value.empty() && !contains_nul(value);
    }

    auto valid_peer_name(std::string_view name) -> bool
    {
      return valid_text(name) && name.size() <= 253U && name.find('*') == std::string_view::npos;
    }

    auto failure(std::string_view operation) -> std::unexpected<std::string>
    {
      return std::unexpected(format_error(operation));
    }
  } // namespace

  auto SslContextDeleter::operator()(SSL_CTX *context) const noexcept -> void
  {
    SSL_CTX_free(context);
  }

  auto SslDeleter::operator()(SSL *session) const noexcept -> void
  {
    SSL_free(session);
  }

  auto BioDeleter::operator()(BIO *bio) const noexcept -> void
  {
    BIO_free(bio);
  }

  auto X509Deleter::operator()(X509 *certificate) const noexcept -> void
  {
    X509_free(certificate);
  }

  auto clear_errors() noexcept -> void
  {
    ERR_clear_error();
  }

  auto format_error(std::string_view operation) -> std::string
  {
    std::string message(operation);
    bool found_error = false;
    for (std::size_t index = 0U; index < MAX_ERROR_ENTRIES; ++index)
    {
      const std::uint32_t error = ERR_get_error();
      if (error == 0U)
        break;

      found_error = true;
      char buffer[ERROR_ENTRY_BUFFER_SIZE]{};
      ERR_error_string_n(error, buffer, sizeof(buffer));
      const std::string_view entry(buffer);
      const std::size_t separator_size = index == 0U ? 2U : 3U;
      if (message.size() + separator_size >= MAX_ERROR_MESSAGE_SIZE)
        break;
      message.append(index == 0U ? ": " : " | ");
      const std::size_t remaining = MAX_ERROR_MESSAGE_SIZE - message.size();
      message.append(entry.substr(0U, remaining));
    }

    while (ERR_get_error() != 0U)
    {
    }

    if (!found_error)
    {
      constexpr std::string_view fallback = ": crypto provider rejected the operation";
      const std::size_t remaining = MAX_ERROR_MESSAGE_SIZE - std::min(message.size(), MAX_ERROR_MESSAGE_SIZE);
      message.append(fallback.substr(0U, remaining));
    }
    if (message.size() > MAX_ERROR_MESSAGE_SIZE)
      message.resize(MAX_ERROR_MESSAGE_SIZE);
    return message;
  }

  auto create_context(const ContextConfig &config) -> Result<Context>
  {
    if (contains_nul(config.credentials.certificate_file) || contains_nul(config.credentials.private_key_file) ||
        contains_nul(config.credentials.trust_store_file))
      return std::unexpected(std::string("TLS credential paths must not contain NUL bytes"));
    const bool has_certificate = valid_text(config.credentials.certificate_file);
    const bool has_private_key = valid_text(config.credentials.private_key_file);
    if (has_certificate != has_private_key)
      return std::unexpected(std::string("TLS certificate and private key must be configured together"));
    if (config.role == Role::server && !has_certificate)
      return std::unexpected(std::string("server TLS configuration requires a certificate and private key"));
    if (config.peer_verification != PeerVerification::none && !valid_text(config.credentials.trust_store_file))
      return std::unexpected(std::string("verified TLS configuration requires a trust store"));
    if (!valid_text(config.profile.key_exchange_group) || !valid_text(config.profile.cipher_suite))
      return std::unexpected(std::string("TLS profile group and cipher must be non-empty"));

    if (config.role == Role::client && !config.allowed_peer_names.empty())
      return std::unexpected(std::string("client peer identity is configured per TLS session"));
    if (config.role == Role::server && config.peer_verification == PeerVerification::certificate_and_identity)
    {
      if (config.allowed_peer_names.empty())
        return std::unexpected(std::string("server TLS configuration requires at least one allowed client name"));
      for (const std::string &name : config.allowed_peer_names)
      {
        if (!valid_peer_name(name))
          return std::unexpected(std::string("server TLS configuration contains an invalid client name"));
      }
    }

    clear_errors();
    SslContextPtr context(SSL_CTX_new(TLS_method()));
    if (!context)
      return failure("create TLS context");
    if (SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context.get(), TLS1_3_VERSION) != 1)
      return failure("enforce TLS 1.3");
    if (SSL_CTX_set1_groups_list(context.get(), config.profile.key_exchange_group.c_str()) != 1)
      return failure("configure TLS key-exchange group");
    if (SSL_CTX_set_ciphersuites(context.get(), config.profile.cipher_suite.c_str()) != 1)
      return failure("configure TLS 1.3 cipher suite");

    SSL_CTX_set_options(context.get(), SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(context.get(), SSL_SESS_CACHE_OFF);
    SSL_CTX_set_early_data_enabled(context.get(), 0);
    SSL_CTX_set_verify_depth(context.get(), MAX_CERTIFICATE_CHAIN_DEPTH);
    int verify_mode = SSL_VERIFY_NONE;
    if (config.peer_verification != PeerVerification::none)
      verify_mode = config.role == Role::server ? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT : SSL_VERIFY_PEER;
    SSL_CTX_set_verify(context.get(), verify_mode, nullptr);

    if (has_certificate)
    {
      if (SSL_CTX_use_certificate_chain_file(context.get(), config.credentials.certificate_file.c_str()) != 1)
        return failure("load local certificate chain");
      if (SSL_CTX_use_PrivateKey_file(context.get(), config.credentials.private_key_file.c_str(), SSL_FILETYPE_PEM) !=
          1)
        return failure("load local private key");
      if (SSL_CTX_check_private_key(context.get()) != 1)
        return failure("validate local certificate and private key");
    }
    if (config.peer_verification != PeerVerification::none &&
        SSL_CTX_load_verify_locations(context.get(), config.credentials.trust_store_file.c_str(), nullptr) != 1)
      return failure("load TLS trust store");

    clear_errors();
    return Context{std::move(context), config.role, config.peer_verification, config.profile,
                   config.allowed_peer_names};
  }
} // namespace ianet::crypto::detail
