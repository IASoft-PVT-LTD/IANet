module;

#include "private/crypto_tls.hpp"

#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <utility>

module ianet.crypto;

namespace ianet::crypto
{
  namespace
  {
    auto to_std_string(const String &value) -> std::string
    {
      return std::string(value.data(), value.size());
    }

    auto to_string(const std::string &value) -> String
    {
      return String(value.c_str());
    }

    auto to_detail_role(TlsRole role) -> detail::Role
    {
      return role == TlsRole::client ? detail::Role::client : detail::Role::server;
    }

    auto to_detail_verification(TlsPeerVerification verification) -> detail::PeerVerification
    {
      switch (verification)
      {
      case TlsPeerVerification::none:
        return detail::PeerVerification::none;
      case TlsPeerVerification::certificate:
        return detail::PeerVerification::certificate;
      case TlsPeerVerification::certificate_and_identity:
        return detail::PeerVerification::certificate_and_identity;
      }
      return detail::PeerVerification::certificate_and_identity;
    }

    auto context_impl(TlsContext &context) -> detail::Context *
    {
      return context ? static_cast<detail::Context *>(context->impl) : nullptr;
    }

    auto session_impl(TlsSession &session) -> detail::Session *
    {
      return session ? static_cast<detail::Session *>(session->impl) : nullptr;
    }

    auto session_impl(const TlsSession &session) -> const detail::Session *
    {
      return session ? static_cast<const detail::Session *>(session->impl) : nullptr;
    }

    auto to_handshake_state(detail::HandshakeState state) -> TlsHandshakeState
    {
      switch (state)
      {
      case detail::HandshakeState::needs_input:
        return TlsHandshakeState::needs_input;
      case detail::HandshakeState::needs_output:
        return TlsHandshakeState::needs_output;
      case detail::HandshakeState::complete:
        return TlsHandshakeState::complete;
      }
      return TlsHandshakeState::needs_input;
    }

    auto to_io_state(detail::IoState state) -> TlsIoState
    {
      switch (state)
      {
      case detail::IoState::complete:
        return TlsIoState::complete;
      case detail::IoState::needs_input:
        return TlsIoState::needs_input;
      case detail::IoState::needs_output:
        return TlsIoState::needs_output;
      case detail::IoState::closed:
        return TlsIoState::closed;
      }
      return TlsIoState::closed;
    }
  } // namespace

  TlsContext_T::~TlsContext_T()
  {
    delete static_cast<detail::Context *>(impl);
    impl = nullptr;
  }

  TlsSession_T::~TlsSession_T()
  {
    delete static_cast<detail::Session *>(impl);
    impl = nullptr;
  }

  auto create_tls_context(const TlsContextConfig &config) -> Result<TlsContext>
  {
    detail::ContextConfig internal{
        .role = to_detail_role(config.role),
        .peer_verification = to_detail_verification(config.peer_verification),
        .credentials =
            {
                .certificate_file = to_std_string(config.credentials.certificate_file),
                .private_key_file = to_std_string(config.credentials.private_key_file),
                .trust_store_file = to_std_string(config.credentials.trust_store_file),
            },
        .profile =
            {
                .key_exchange_group = to_std_string(config.profile.key_exchange_group),
                .cipher_suite = to_std_string(config.profile.cipher_suite),
            },
    };
    internal.allowed_peer_names.reserve(config.allowed_peer_names.size());
    for (const String &name : config.allowed_peer_names)
      internal.allowed_peer_names.push_back(to_std_string(name));

    auto result = detail::create_context(internal);
    if (!result)
      return fail("create crypto TLS context failed: {}", result.error());

    auto impl = std::unique_ptr<detail::Context>(new (std::nothrow) detail::Context(std::move(result.value())));
    if (!impl)
      return fail("allocate crypto TLS context failed");
    auto context = make_box<TlsContext_T>();
    context->impl = impl.release();
    return context;
  }

  auto create_tls_session(TlsContext &context, const String &expected_peer_name) -> Result<TlsSession>
  {
    auto *impl = context_impl(context);
    if (impl == nullptr)
      return fail("crypto TLS context is not initialized");
    auto result = detail::create_session(*impl, to_std_string(expected_peer_name));
    if (!result)
      return fail("create crypto TLS session failed: {}", result.error());

    auto session_impl = std::unique_ptr<detail::Session>(new (std::nothrow) detail::Session(std::move(result.value())));
    if (!session_impl)
      return fail("allocate crypto TLS session failed");
    auto session = make_box<TlsSession_T>();
    session->impl = session_impl.release();
    return session;
  }

  auto tls_handshake_step(TlsSession &session) -> Result<TlsHandshakeState>
  {
    auto *impl = session_impl(session);
    if (impl == nullptr)
      return fail("crypto TLS session is not initialized");
    auto result = detail::handshake_step(*impl);
    if (!result)
      return fail("{}", result.error());
    return to_handshake_state(result.value());
  }

  auto tls_negotiated_profile(TlsSession &session) -> Result<TlsNegotiatedProfile>
  {
    auto *impl = session_impl(session);
    if (impl == nullptr || !impl->authenticated || !impl->native)
      return fail("crypto TLS session is not authenticated");

    const char *group = SSL_get_group_name(SSL_get_group_id(impl->native.get()));
    const SSL_CIPHER *cipher = SSL_get_current_cipher(impl->native.get());
    if (group == nullptr || cipher == nullptr)
      return fail("crypto TLS negotiated profile is unavailable");

    return TlsNegotiatedProfile{
        .protocol_version = String(SSL_get_version(impl->native.get())),
        .key_exchange_group = String(group),
        .cipher_suite = String(SSL_CIPHER_get_name(cipher)),
        .peer_verified = impl->peer_verification != detail::PeerVerification::none &&
                         SSL_get_verify_result(impl->native.get()) == X509_V_OK,
        .session_reused = SSL_session_reused(impl->native.get()) != 0,
        .early_data_accepted = SSL_early_data_accepted(impl->native.get()) != 0,
    };
  }

  auto tls_write_step(TlsSession &session, Span<const u8> plaintext) -> Result<TlsIoResult>
  {
    auto *impl = session_impl(session);
    if (impl == nullptr)
      return fail("crypto TLS session is not initialized");
    auto result = detail::write_step(
        *impl,
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(plaintext.data()), plaintext.size()));
    if (!result)
      return fail("{}", result.error());
    return TlsIoResult{to_io_state(result->state), result->size};
  }

  auto tls_read_step(TlsSession &session, Span<u8> plaintext) -> Result<TlsIoResult>
  {
    auto *impl = session_impl(session);
    if (impl == nullptr)
      return fail("crypto TLS session is not initialized");
    auto result = detail::read_step(
        *impl, std::span<std::uint8_t>(reinterpret_cast<std::uint8_t *>(plaintext.data()), plaintext.size()));
    if (!result)
      return fail("{}", result.error());
    return TlsIoResult{to_io_state(result->state), result->size};
  }

  auto tls_shutdown_step(TlsSession &session) -> Result<TlsShutdownState>
  {
    auto *impl = session_impl(session);
    if (impl == nullptr)
      return fail("crypto TLS session is not initialized");
    auto result = detail::shutdown_step(*impl);
    if (!result)
      return fail("{}", result.error());
    switch (result.value())
    {
    case detail::ShutdownState::complete:
      return TlsShutdownState::complete;
    case detail::ShutdownState::needs_input:
      return TlsShutdownState::needs_input;
    case detail::ShutdownState::needs_output:
      return TlsShutdownState::needs_output;
    }
    return fail("crypto TLS returned an invalid shutdown state");
  }

  auto pending_tls_ciphertext(const TlsSession &session) -> usize
  {
    const auto *impl = session_impl(session);
    return impl == nullptr ? 0U : detail::pending_ciphertext(*impl);
  }

  auto take_tls_ciphertext(TlsSession &session) -> Result<Vec<u8>>
  {
    auto *impl = session_impl(session);
    if (impl == nullptr)
      return fail("crypto TLS session is not initialized");
    auto result = detail::take_ciphertext(*impl);
    if (!result)
      return fail("{}", result.error());
    auto bytes = std::move(result.value());
    Vec<u8> output;
    output.insert(output.end(), bytes.begin(), bytes.end());
    return output;
  }

  auto provide_tls_ciphertext(TlsSession &session, Span<const u8> ciphertext) -> Result<void>
  {
    auto *impl = session_impl(session);
    if (impl == nullptr)
      return fail("crypto TLS session is not initialized");
    auto result = detail::provide_ciphertext(
        *impl,
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(ciphertext.data()), ciphertext.size()));
    if (!result)
      return fail("{}", result.error());
    return Result<void>();
  }
} // namespace ianet::crypto
