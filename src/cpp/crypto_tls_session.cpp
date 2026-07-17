#include "private/crypto_tls.hpp"

#include <openssl/x509.h>

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace ianet::crypto::detail
{
  namespace
  {
    auto contains_nul(std::string_view value) -> bool
    {
      return value.find('\0') != std::string_view::npos;
    }

    auto valid_peer_name(std::string_view name) -> bool
    {
      return !name.empty() && name.size() <= 253U && !contains_nul(name);
    }

    auto is_ip_address(const char *name) -> bool
    {
      std::array<unsigned char, 16U> storage{};
      return inet_pton(AF_INET, name, storage.data()) == 1 || inet_pton(AF_INET6, name, storage.data()) == 1;
    }

    auto certificate_matches_name(const X509 *certificate, const std::string &name) -> bool
    {
      if (is_ip_address(name.c_str()))
        return X509_check_ip_asc(certificate, name.c_str(), 0U) == 1;
      return X509_check_host(certificate, name.c_str(), name.size(), X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 1;
    }

    auto configure_client_identity(SSL *ssl, const std::string &expected_name) -> Result<void>
    {
      if (is_ip_address(expected_name.c_str()))
      {
        if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), expected_name.c_str()) != 1)
          return std::unexpected(format_error("configure expected server IP identity"));
        return {};
      }

      SSL_set_hostflags(ssl, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
      if (SSL_set1_host(ssl, expected_name.c_str()) != 1)
        return std::unexpected(format_error("configure expected server DNS identity"));
      if (SSL_set_tlsext_host_name(ssl, expected_name.c_str()) != 1)
        return std::unexpected(format_error("configure TLS server name indication"));
      return {};
    }

    auto verify_peer_identity(const Session &session, const X509 *certificate) -> Result<void>
    {
      for (const std::string &name : session.expected_peer_names)
      {
        if (certificate_matches_name(certificate, name))
          return {};
      }
      return std::unexpected(std::string("authenticated peer certificate does not match an allowed identity"));
    }
  } // namespace

  auto create_session(Context &context, std::string_view expected_peer_name) -> Result<Session>
  {
    if (!context.native)
      return std::unexpected(std::string("cannot create a TLS session from an empty context"));
    if (context.role == Role::client && !valid_peer_name(expected_peer_name))
      return std::unexpected(std::string("client TLS session requires a valid expected server name"));
    if (context.role == Role::server && !expected_peer_name.empty())
      return std::unexpected(std::string("server peer identities must be configured on the TLS context"));

    clear_errors();
    SslPtr ssl(SSL_new(context.native.get()));
    if (!ssl)
      return std::unexpected(format_error("create TLS session"));

    BioPtr inbound(BIO_new(BIO_s_mem()));
    BioPtr outbound(BIO_new(BIO_s_mem()));
    if (!inbound || !outbound)
      return std::unexpected(format_error("create TLS memory BIOs"));
    if (BIO_set_mem_eof_return(inbound.get(), -1) != 1)
      return std::unexpected(format_error("configure TLS input BIO"));
    SSL_set_bio(ssl.get(), inbound.release(), outbound.release());

    std::vector<std::string> expected_names;
    if (context.role == Role::client)
    {
      SSL_set_connect_state(ssl.get());
      expected_names.emplace_back(expected_peer_name);
      auto identity_result = configure_client_identity(ssl.get(), expected_names.front());
      if (!identity_result)
        return std::unexpected(std::move(identity_result.error()));
    }
    else
    {
      SSL_set_accept_state(ssl.get());
      expected_names = context.allowed_peer_names;
    }

    Session session{std::move(ssl), nullptr, nullptr, context.role, context.profile, std::move(expected_names), false};
    session.inbound = SSL_get_rbio(session.native.get());
    session.outbound = SSL_get_wbio(session.native.get());
    clear_errors();
    return session;
  }

  auto validate_profile(const Session &session) -> Result<void>
  {
    if (!session.native)
      return std::unexpected(std::string("cannot validate an empty TLS session"));
    if (!SSL_is_init_finished(session.native.get()))
      return std::unexpected(std::string("TLS handshake is not complete"));
    if (SSL_version(session.native.get()) != TLS1_3_VERSION)
      return std::unexpected(std::string("TLS peer negotiated a disallowed protocol version"));

    const char *group_name = SSL_get_group_name(SSL_get_group_id(session.native.get()));
    if (group_name == nullptr || session.profile.key_exchange_group != group_name)
      return std::unexpected(std::string("TLS peer negotiated a disallowed key-exchange group"));

    const SSL_CIPHER *cipher = SSL_get_current_cipher(session.native.get());
    if (cipher == nullptr || session.profile.cipher_suite != SSL_CIPHER_get_name(cipher))
      return std::unexpected(std::string("TLS peer negotiated a disallowed cipher suite"));
    if (SSL_get_verify_result(session.native.get()) != X509_V_OK)
      return std::unexpected(std::string("TLS peer certificate verification failed"));
    if (SSL_session_reused(session.native.get()) != 0)
      return std::unexpected(std::string("TLS session resumption is disabled"));
    if (SSL_early_data_accepted(session.native.get()) != 0)
      return std::unexpected(std::string("TLS early data is disabled"));

    X509Ptr peer_certificate(SSL_get_peer_certificate(session.native.get()));
    if (!peer_certificate)
      return std::unexpected(std::string("TLS peer did not provide a certificate"));
    return verify_peer_identity(session, peer_certificate.get());
  }

  auto handshake_step(Session &session) -> Result<HandshakeState>
  {
    if (!session.native)
      return std::unexpected(std::string("cannot handshake an empty TLS session"));
    if (session.authenticated)
      return HandshakeState::complete;

    clear_errors();
    const int result = SSL_do_handshake(session.native.get());
    if (result == 1)
    {
      auto validation_result = validate_profile(session);
      if (!validation_result)
        return std::unexpected(std::move(validation_result.error()));
      session.authenticated = true;
      clear_errors();
      return HandshakeState::complete;
    }

    const int error = SSL_get_error(session.native.get(), result);
    if (error == SSL_ERROR_WANT_READ)
      return HandshakeState::needs_input;
    if (error == SSL_ERROR_WANT_WRITE)
      return HandshakeState::needs_output;
    return std::unexpected(format_error("TLS handshake failed"));
  }

  auto write_step(Session &session, std::span<const std::uint8_t> plaintext) -> Result<IoResult>
  {
    if (!session.native || !session.authenticated)
      return std::unexpected(std::string("cannot write before TLS authentication completes"));
    if (plaintext.empty())
      return IoResult{IoState::complete, 0U};

    const std::size_t size = std::min(plaintext.size(), static_cast<std::size_t>(std::numeric_limits<int>::max()));
    clear_errors();
    const int result = SSL_write(session.native.get(), plaintext.data(), static_cast<int>(size));
    if (result > 0)
      return IoResult{IoState::complete, static_cast<std::size_t>(result)};
    const int error = SSL_get_error(session.native.get(), result);
    if (error == SSL_ERROR_WANT_READ)
      return IoResult{IoState::needs_input, 0U};
    if (error == SSL_ERROR_WANT_WRITE)
      return IoResult{IoState::needs_output, 0U};
    if (error == SSL_ERROR_ZERO_RETURN)
      return IoResult{IoState::closed, 0U};
    return std::unexpected(format_error("TLS write failed"));
  }

  auto read_step(Session &session, std::span<std::uint8_t> plaintext) -> Result<IoResult>
  {
    if (!session.native || !session.authenticated)
      return std::unexpected(std::string("cannot read before TLS authentication completes"));
    if (plaintext.empty())
      return IoResult{IoState::complete, 0U};

    const std::size_t size = std::min(plaintext.size(), static_cast<std::size_t>(std::numeric_limits<int>::max()));
    clear_errors();
    const int result = SSL_read(session.native.get(), plaintext.data(), static_cast<int>(size));
    if (result > 0)
      return IoResult{IoState::complete, static_cast<std::size_t>(result)};
    const int error = SSL_get_error(session.native.get(), result);
    if (error == SSL_ERROR_WANT_READ)
      return IoResult{IoState::needs_input, 0U};
    if (error == SSL_ERROR_WANT_WRITE)
      return IoResult{IoState::needs_output, 0U};
    if (error == SSL_ERROR_ZERO_RETURN)
      return IoResult{IoState::closed, 0U};
    return std::unexpected(format_error("TLS read failed"));
  }

  auto shutdown_step(Session &session) -> Result<ShutdownState>
  {
    if (!session.native || !session.authenticated)
      return std::unexpected(std::string("cannot shut down an unauthenticated TLS session"));
    clear_errors();
    const int result = SSL_shutdown(session.native.get());
    if (result == 1)
      return ShutdownState::complete;
    if (result == 0)
      return ShutdownState::needs_input;
    const int error = SSL_get_error(session.native.get(), result);
    if (error == SSL_ERROR_WANT_READ)
      return ShutdownState::needs_input;
    if (error == SSL_ERROR_WANT_WRITE)
      return ShutdownState::needs_output;
    return std::unexpected(format_error("TLS shutdown failed"));
  }

  auto pending_ciphertext(const Session &session) noexcept -> std::size_t
  {
    return session.outbound == nullptr ? 0U : BIO_ctrl_pending(session.outbound);
  }

  auto take_ciphertext(Session &session) -> Result<std::vector<std::uint8_t>>
  {
    if (session.outbound == nullptr)
      return std::unexpected(std::string("TLS session has no output BIO"));
    const std::size_t pending = pending_ciphertext(session);
    if (pending == 0U)
      return std::vector<std::uint8_t>{};
    const std::size_t size = std::min(pending, MAX_CIPHERTEXT_CHUNK_SIZE);
    std::vector<std::uint8_t> ciphertext(size);
    const int read = BIO_read(session.outbound, ciphertext.data(), static_cast<int>(ciphertext.size()));
    if (read <= 0)
      return std::unexpected(format_error("drain TLS output BIO"));
    ciphertext.resize(static_cast<std::size_t>(read));
    return ciphertext;
  }

  auto provide_ciphertext(Session &session, std::span<const std::uint8_t> ciphertext) -> Result<void>
  {
    if (session.inbound == nullptr)
      return std::unexpected(std::string("TLS session has no input BIO"));
    if (ciphertext.empty())
      return {};
    if (ciphertext.size() > MAX_CIPHERTEXT_CHUNK_SIZE)
      return std::unexpected(std::string("TLS ciphertext input exceeds the per-call limit"));
    const std::size_t buffered = BIO_ctrl_pending(session.inbound);
    if (buffered > MAX_BUFFERED_CIPHERTEXT_SIZE - ciphertext.size())
      return std::unexpected(std::string("TLS ciphertext input exceeds the buffered limit"));
    clear_errors();
    if (BIO_write_all(session.inbound, ciphertext.data(), ciphertext.size()) != 1)
      return std::unexpected(format_error("feed TLS input BIO"));
    clear_errors();
    return {};
  }
} // namespace ianet::crypto::detail
