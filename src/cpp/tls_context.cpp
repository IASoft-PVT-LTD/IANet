/**
 * @file tls_context.cpp
 * @brief Socket-attached TLS compatibility API implemented through ianet.crypto.
 */

module;

#include <auxid/macros.hpp>

#if AU_PLATFORM_WINDOWS
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <cerrno>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <utility>

module ianet.tls;

import ianet.crypto;

namespace
{
  using namespace au;
  namespace tls = ianet::crypto;

  constexpr usize MAX_PUMP_STEPS = 512U;
  constexpr usize MAX_HANDSHAKE_CIPHERTEXT = 4U * 1024U * 1024U;
  // Offer the post-quantum hybrid group first (kept preferred), then classical
  // X25519 and P-256 as fallbacks so the handshake still completes against peers
  // that lack MLKEM support (e.g. OpenSSL 3.0.x nginx, which returns
  // "no suitable key share" when only X25519MLKEM768 is offered). The names are
  // the AWS-LC group tokens accepted by SSL_CTX_set1_groups_list (colon list,
  // first = most preferred).
  constexpr const char *DEFAULT_GROUP = "X25519MLKEM768:X25519:P-256";
  constexpr const char *DEFAULT_CIPHER = "TLS_CHACHA20_POLY1305_SHA256";

  struct SocketTlsContext
  {
    tls::TlsContext context;
    bool is_server{};
    String expected_peer_name;
  };

  struct SocketTlsSession
  {
    tls::TlsSession session;
    ianet::NativeSocket *socket{};
  };

  auto to_std_string(const String &value) -> std::string
  {
    return std::string(value.data(), value.size());
  }

  auto copy_error(char *buffer, std::size_t buffer_size, const std::string &error) -> void
  {
    if (buffer == nullptr || buffer_size == 0U)
      return;
    const std::size_t size = std::min(buffer_size - 1U, error.size());
    std::memcpy(buffer, error.data(), size);
    buffer[size] = '\0';
  }

  auto raw_send_all(ianet::NativeSocket socket, Span<const u8> data) -> Result<void>
  {
    usize offset = 0U;
    while (offset < data.size())
    {
#if AU_PLATFORM_WINDOWS
      const usize remaining = data.size() - offset;
      const int chunk = remaining > static_cast<usize>(INT_MAX) ? INT_MAX : static_cast<int>(remaining);
      const int sent = send(socket, reinterpret_cast<const char *>(data.data() + offset), chunk, 0);
      if (sent == SOCKET_ERROR)
        return fail("TLS socket send failed: {}", WSAGetLastError());
#else
      const ssize_t sent = ::send(socket, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
      if (sent < 0)
      {
        if (errno == EINTR)
          continue;
        return fail("TLS socket send failed: {}", errno);
      }
#endif
      if (sent == 0)
        return fail("TLS socket send returned zero");
      offset += static_cast<usize>(sent);
    }
    return Result<void>();
  }

  auto flush_ciphertext(SocketTlsSession &session) -> Result<usize>
  {
    usize total = 0U;
    while (tls::pending_tls_ciphertext(session.session) != 0U)
    {
      auto result = tls::take_tls_ciphertext(session.session);
      if (result.is_err())
        return fail(result.error());
      auto ciphertext = std::move(result.unwrap());
      if (ciphertext.empty())
        return fail("TLS output reported pending ciphertext but returned none");
      auto send_result = raw_send_all(*session.socket, Span<const u8>(ciphertext.data(), ciphertext.size()));
      if (send_result.is_err())
        return fail(send_result.error());
      total += ciphertext.size();
    }
    return total;
  }

  auto receive_ciphertext(SocketTlsSession &session) -> Result<usize>
  {
    std::array<u8, tls::MAX_TLS_CIPHERTEXT_CHUNK_SIZE> buffer{};
#if AU_PLATFORM_WINDOWS
    const int received =
        recv(*session.socket, reinterpret_cast<char *>(buffer.data()), static_cast<int>(buffer.size()), 0);
    if (received == SOCKET_ERROR)
      return fail("TLS socket receive failed: {}", WSAGetLastError());
#else
    ssize_t received = -1;
    do
    {
      received = ::recv(*session.socket, buffer.data(), buffer.size(), 0);
    } while (received < 0 && errno == EINTR);
    if (received < 0)
      return fail("TLS socket receive failed: {}", errno);
#endif
    if (received == 0)
      return fail("TLS socket closed without close_notify");
    auto result =
        tls::provide_tls_ciphertext(session.session, Span<const u8>(buffer.data(), static_cast<usize>(received)));
    if (result.is_err())
      return fail(result.error());
    return static_cast<usize>(received);
  }

  auto pump_handshake(SocketTlsSession &session) -> Result<void>
  {
    usize received_total = 0U;
    for (usize step = 0U; step < MAX_PUMP_STEPS; ++step)
    {
      auto handshake = tls::tls_handshake_step(session.session);
      if (handshake.is_err())
        return fail(handshake.error());
      auto flushed = flush_ciphertext(session);
      if (flushed.is_err())
        return fail(flushed.error());
      if (handshake.unwrap() == tls::TlsHandshakeState::complete)
        return Result<void>();
      if (handshake.unwrap() == tls::TlsHandshakeState::needs_output)
      {
        if (flushed.unwrap() == 0U)
          return fail("TLS handshake requested output without producing ciphertext");
        continue;
      }
      auto received = receive_ciphertext(session);
      if (received.is_err())
        return fail(received.error());
      received_total += received.unwrap();
      if (received_total > MAX_HANDSHAKE_CIPHERTEXT)
        return fail("TLS handshake exceeded ciphertext limit");
    }
    return fail("TLS handshake exceeded progress limit");
  }

  auto send_plaintext(SocketTlsSession &session, Span<const u8> plaintext) -> Result<void>
  {
    usize offset = 0U;
    usize stalled = 0U;
    while (offset < plaintext.size())
    {
      auto write = tls::tls_write_step(session.session, plaintext.subspan(offset));
      if (write.is_err())
        return fail(write.error());
      const tls::TlsIoResult io = write.unwrap();
      offset += io.size;
      auto flushed = flush_ciphertext(session);
      if (flushed.is_err())
        return fail(flushed.error());
      if (io.state == tls::TlsIoState::closed)
        return fail("TLS peer closed during write");
      if (io.state == tls::TlsIoState::needs_input)
      {
        auto received = receive_ciphertext(session);
        if (received.is_err())
          return fail(received.error());
      }
      else if (io.state == tls::TlsIoState::needs_output && flushed.unwrap() == 0U)
      {
        return fail("TLS write requested output without producing ciphertext");
      }

      const bool progress = io.size != 0U || flushed.unwrap() != 0U;
      stalled = progress ? 0U : stalled + 1U;
      if (stalled > MAX_PUMP_STEPS)
        return fail("TLS write exceeded progress limit");
    }
    return Result<void>();
  }

  auto receive_plaintext(SocketTlsSession &session, Span<u8> plaintext, usize &read_size) -> Result<void>
  {
    read_size = 0U;
    if (plaintext.empty())
      return Result<void>();
    for (;;)
    {
      auto read = tls::tls_read_step(session.session, plaintext);
      if (read.is_err())
        return fail(read.error());
      const tls::TlsIoResult io = read.unwrap();
      auto flushed = flush_ciphertext(session);
      if (flushed.is_err())
        return fail(flushed.error());
      if (io.state == tls::TlsIoState::complete)
      {
        read_size = io.size;
        return Result<void>();
      }
      if (io.state == tls::TlsIoState::closed)
        return Result<void>();
      if (io.state == tls::TlsIoState::needs_input)
      {
        auto received = receive_ciphertext(session);
        if (received.is_err())
          return fail(received.error());
      }
      else if (flushed.unwrap() == 0U)
      {
        return fail("TLS read requested output without producing ciphertext");
      }
    }
  }

  auto close_session(SocketTlsSession &session) -> Result<void>
  {
    auto shutdown = tls::tls_shutdown_step(session.session);
    if (shutdown.is_err())
      return fail(shutdown.error());
    auto flushed = flush_ciphertext(session);
    if (flushed.is_err())
      return fail(flushed.error());
    return Result<void>();
  }

  auto make_profile() -> tls::TlsProfile
  {
    return tls::TlsProfile{
        .key_exchange_group = String(DEFAULT_GROUP),
        .cipher_suite = String(DEFAULT_CIPHER),
    };
  }
} // namespace

/// @cond INTERNAL
extern "C"
{
  void ianet_tls_session_free(void *tls_session)
  {
    if (tls_session == nullptr)
      return;
    auto *session = static_cast<SocketTlsSession *>(tls_session);
    (void) close_session(*session);
    delete session;
  }

  int ianet_tls_session_send(void *tls_session, const unsigned char *data, size_t length, char *error_buffer,
                             size_t error_buffer_size)
  {
    if (tls_session == nullptr || (data == nullptr && length != 0U))
    {
      copy_error(error_buffer, error_buffer_size, "invalid TLS send arguments");
      return -1;
    }
    auto *session = static_cast<SocketTlsSession *>(tls_session);
    auto result = send_plaintext(*session, Span<const u8>(data, length));
    if (result.is_err())
    {
      copy_error(error_buffer, error_buffer_size, to_std_string(result.error()));
      return -1;
    }
    return 0;
  }

  int ianet_tls_session_recv(void *tls_session, unsigned char *buffer, size_t length, size_t *out_read,
                             char *error_buffer, size_t error_buffer_size)
  {
    if (tls_session == nullptr || out_read == nullptr || (buffer == nullptr && length != 0U))
    {
      copy_error(error_buffer, error_buffer_size, "invalid TLS receive arguments");
      return -1;
    }
    auto *session = static_cast<SocketTlsSession *>(tls_session);
    usize read_size = 0U;
    auto result = receive_plaintext(*session, Span<u8>(buffer, length), read_size);
    if (result.is_err())
    {
      copy_error(error_buffer, error_buffer_size, to_std_string(result.error()));
      return -1;
    }
    *out_read = read_size;
    return 0;
  }
}

/// @endcond

namespace ianet
{
  using namespace au;

  TlsContext_T::~TlsContext_T()
  {
    delete static_cast<SocketTlsContext *>(impl);
    impl = nullptr;
  }

  auto __tls_context_impl(TlsContext &tls) -> void *
  {
    return tls ? tls->impl : nullptr;
  }

  auto __tls_context_is_server(TlsContext &tls) -> bool
  {
    auto *impl = static_cast<SocketTlsContext *>(__tls_context_impl(tls));
    return impl != nullptr && impl->is_server;
  }

  auto __setup_tls_session(NativeSocket *socket, TlsContext &tls_context, const String &peer_name) -> Result<void *>
  {
    auto *context = static_cast<SocketTlsContext *>(__tls_context_impl(tls_context));
    if (socket == nullptr || context == nullptr)
      return fail("invalid TLS socket or context");

    auto session_result = crypto::create_tls_session(context->context, peer_name);
    if (session_result.is_err())
      return fail(session_result.error());
    auto session = std::unique_ptr<SocketTlsSession>(new (std::nothrow)
                                                         SocketTlsSession{std::move(session_result.unwrap()), socket});
    if (!session)
      return fail("allocate socket TLS session failed");
    auto handshake = pump_handshake(*session);
    if (handshake.is_err())
      return fail(handshake.error());
    return session.release();
  }

  auto create_tls_server_context(const TlsConfig &config) -> Result<TlsContext>
  {
    crypto::TlsContextConfig crypto_config{
        .role = crypto::TlsRole::server,
        .peer_verification = config.verify_mode == ETlsVerifyMode::Required && !config.ca_file.empty()
                                 ? crypto::TlsPeerVerification::certificate
                                 : crypto::TlsPeerVerification::none,
        .credentials =
            {
                .certificate_file = config.cert_file,
                .private_key_file = config.key_file,
                .trust_store_file = config.ca_file,
            },
        .profile = make_profile(),
    };
    auto result = crypto::create_tls_context(crypto_config);
    if (result.is_err())
      return fail(result.error());
    auto impl =
        std::unique_ptr<SocketTlsContext>(new (std::nothrow) SocketTlsContext{std::move(result.unwrap()), true, {}});
    if (!impl)
      return fail("allocate server TLS context failed");
    auto context = make_box<TlsContext_T>();
    context->impl = impl.release();
    return context;
  }

  auto create_tls_client_context(const TlsConfig &config) -> Result<TlsContext>
  {
    crypto::TlsContextConfig crypto_config{
        .role = crypto::TlsRole::client,
        .peer_verification = config.verify_mode == ETlsVerifyMode::Required
                                 ? crypto::TlsPeerVerification::certificate_and_identity
                                 : crypto::TlsPeerVerification::none,
        .credentials =
            {
                .certificate_file = config.cert_file,
                .private_key_file = config.key_file,
                .trust_store_file = config.ca_file,
            },
        .profile = make_profile(),
    };
    auto result = crypto::create_tls_context(crypto_config);
    if (result.is_err())
      return fail(result.error());
    auto impl = std::unique_ptr<SocketTlsContext>(
        new (std::nothrow) SocketTlsContext{std::move(result.unwrap()), false, config.expected_peer_name});
    if (!impl)
      return fail("allocate client TLS context failed");
    auto context = make_box<TlsContext_T>();
    context->impl = impl.release();
    return context;
  }

  auto tls_client_connect(SocketClient &client, const String &address, u16 port, TlsContext &tls) -> Result<Connection>
  {
    if (__tls_context_is_server(tls))
      return fail("TLS context is configured for server use");
    auto connection_result = socket_client_connect(client, address, port);
    if (connection_result.is_err())
      return fail("failed to connect: {}", connection_result.error());
    auto connection = std::move(connection_result.unwrap());
    auto *context = static_cast<SocketTlsContext *>(__tls_context_impl(tls));
    const String &peer_name = context->expected_peer_name.empty() ? address : context->expected_peer_name;
    auto session_result = __setup_tls_session(&connection->sock, tls, peer_name);
    if (session_result.is_err())
      return fail(session_result.error());
    connection->tls = session_result.unwrap();
    return connection;
  }

  auto tls_server_accept(SocketServer &server, TlsContext &tls) -> Result<Connection>
  {
    if (!__tls_context_is_server(tls))
      return fail("TLS context is configured for client use");
    auto connection_result = socket_server_accept(server);
    if (connection_result.is_err())
      return fail("failed to accept connection: {}", connection_result.error());
    auto connection = std::move(connection_result.unwrap());
    auto session_result = __setup_tls_session(&connection->sock, tls, String{});
    if (session_result.is_err())
      return fail(session_result.error());
    connection->tls = session_result.unwrap();
    return connection;
  }
} // namespace ianet
