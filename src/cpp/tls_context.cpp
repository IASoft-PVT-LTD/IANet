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
#include <cstring>
#include <utility>

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

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <cstddef>

extern "C" {

void ianet_tls_session_free(void *tls)
{
  if (tls == nullptr)
    return;

  auto *ssl = static_cast<mbedtls_ssl_context *>(tls);
  mbedtls_ssl_free(ssl);
  delete ssl;
}

void ianet_tls_format_error(int code, char *buf, size_t buf_len)
{
  if (buf == nullptr || buf_len == 0)
    return;

  mbedtls_strerror(code, buf, buf_len);
}

int ianet_tls_session_send(void *tls, const unsigned char *data, size_t len)
{
  if (tls == nullptr || data == nullptr)
    return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;

  auto *ssl = static_cast<mbedtls_ssl_context *>(tls);

  size_t off = 0;
  while (off < len)
  {
    const int written = mbedtls_ssl_write(ssl, data + off, len - off);
    if (written <= 0)
    {
      if (written == MBEDTLS_ERR_SSL_WANT_READ || written == MBEDTLS_ERR_SSL_WANT_WRITE)
        continue;

      return written;
    }

    off += static_cast<size_t>(written);
  }

  return 0;
}

int ianet_tls_session_recv(void *tls, unsigned char *buf, size_t len, size_t *out_read)
{
  if (out_read == nullptr)
    return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;

  *out_read = 0;

  if (tls == nullptr || buf == nullptr)
    return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;

  if (len == 0)
    return 0;

  auto *ssl = static_cast<mbedtls_ssl_context *>(tls);

  while (true)
  {
    const int read = mbedtls_ssl_read(ssl, buf, len);
    if (read == MBEDTLS_ERR_SSL_WANT_READ || read == MBEDTLS_ERR_SSL_WANT_WRITE)
      continue;

    if (read <= 0)
    {
      if (read == 0 || read == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        return 0;

      return read;
    }

    *out_read = static_cast<size_t>(read);
    return 0;
  }
}

} // extern "C"

module ianet.tls;

namespace ianet
{
  using namespace au;

  namespace
  {
    struct MbedTlsGlobal
    {
      mbedtls_entropy_context entropy{};
      mbedtls_ctr_drbg_context ctr_drbg{};

      MbedTlsGlobal()
      {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        const char pers[] = "ianet";
        const int seed_ret = mbedtls_ctr_drbg_seed(
            &ctr_drbg, mbedtls_entropy_func, &entropy, reinterpret_cast<const unsigned char *>(pers),
            sizeof(pers) - 1);
        if (seed_ret != 0)
          au::panic_at("mbedtls_ctr_drbg_seed failed", __FILE__, __LINE__);
      }

      ~MbedTlsGlobal()
      {
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
      }

      MbedTlsGlobal(const MbedTlsGlobal &) = delete;
      auto operator=(const MbedTlsGlobal &) -> MbedTlsGlobal & = delete;
    };

    auto get_mbedtls_global() -> MbedTlsGlobal &
    {
      static MbedTlsGlobal global;
      return global;
    }

    struct TlsContextImpl
    {
      mbedtls_ssl_config conf{};
      mbedtls_x509_crt own_cert{};
      mbedtls_pk_context own_key{};
      mbedtls_x509_crt ca_chain{};
      bool is_server{false};

      TlsContextImpl()
      {
        mbedtls_ssl_config_init(&conf);
        mbedtls_x509_crt_init(&own_cert);
        mbedtls_pk_init(&own_key);
        mbedtls_x509_crt_init(&ca_chain);
      }

      ~TlsContextImpl()
      {
        mbedtls_ssl_config_free(&conf);
        mbedtls_x509_crt_free(&own_cert);
        mbedtls_pk_free(&own_key);
        mbedtls_x509_crt_free(&ca_chain);
      }

      TlsContextImpl(const TlsContextImpl &) = delete;
      auto operator=(const TlsContextImpl &) -> TlsContextImpl & = delete;
    };

    auto tls_bio_send(void *ctx, const unsigned char *buf, size_t len) -> int
    {
      auto *sock = static_cast<NativeSocket *>(ctx);

#if AU_PLATFORM_WINDOWS
      const int chunk = len > static_cast<size_t>(INT_MAX) ? INT_MAX : static_cast<int>(len);
      const int sent = send(*sock, reinterpret_cast<const char *>(buf), chunk, 0);
      if (sent == SOCKET_ERROR)
      {
        const int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK)
          return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_NET_SEND_FAILED;
      }
      return sent;
#else
      const ssize_t sent = ::send(*sock, reinterpret_cast<const char *>(buf), len, 0);
      if (sent < 0)
      {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_NET_SEND_FAILED;
      }
      return static_cast<int>(sent);
#endif
    }

    auto tls_bio_recv(void *ctx, unsigned char *buf, size_t len) -> int
    {
      auto *sock = static_cast<NativeSocket *>(ctx);

#if AU_PLATFORM_WINDOWS
      const int chunk = len > static_cast<size_t>(INT_MAX) ? INT_MAX : static_cast<int>(len);
      const int received = recv(*sock, reinterpret_cast<char *>(buf), chunk, 0);
      if (received == SOCKET_ERROR)
      {
        const int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK)
          return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_NET_RECV_FAILED;
      }
      if (received == 0)
        return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
      return received;
#else
      const ssize_t received = ::recv(*sock, reinterpret_cast<char *>(buf), len, 0);
      if (received < 0)
      {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_NET_RECV_FAILED;
      }
      if (received == 0)
        return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
      return static_cast<int>(received);
#endif
    }

    auto tls_do_handshake(mbedtls_ssl_context &ssl) -> Result<void>
    {
      int ret = 0;
      while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
      {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
          continue;

        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        return fail("TLS handshake failed: {} ({})", ret, err_buf);
      }

      return Result<void>();
    }

    auto setup_tls_session(NativeSocket *sock, TlsContextImpl &ctx, const char *hostname) -> Result<void *>
    {
      if (sock == nullptr)
        return fail("invalid socket for TLS session");

      auto *ssl = new mbedtls_ssl_context();
      mbedtls_ssl_init(ssl);

      int ret = mbedtls_ssl_setup(ssl, &ctx.conf);
      if (ret != 0)
      {
        mbedtls_ssl_free(ssl);
        delete ssl;
        return fail("mbedtls_ssl_setup failed: {}", ret);
      }

      if (hostname != nullptr && hostname[0] != '\0')
      {
        ret = mbedtls_ssl_set_hostname(ssl, hostname);
        if (ret != 0)
        {
          mbedtls_ssl_free(ssl);
          delete ssl;
          return fail("mbedtls_ssl_set_hostname failed: {}", ret);
        }
      }

      mbedtls_ssl_set_bio(ssl, sock, tls_bio_send, tls_bio_recv, nullptr);

      auto hs_r = tls_do_handshake(*ssl);
      if (hs_r.is_err())
      {
        mbedtls_ssl_free(ssl);
        delete ssl;
        return fail("{}", hs_r.error());
      }

      return ssl;
    }

    auto load_pem_cert(mbedtls_x509_crt &chain, const String &path) -> Result<void>
    {
      if (path.empty())
        return fail("certificate path is empty");

      const int ret = mbedtls_x509_crt_parse_file(&chain, path.c_str());
      if (ret != 0)
        return fail("failed to parse certificate '{}': {}", path, ret);

      return Result<void>();
    }

    auto load_pem_key(mbedtls_pk_context &key, const String &path) -> Result<void>
    {
      if (path.empty())
        return fail("private key path is empty");

      const int ret = mbedtls_pk_parse_keyfile(&key, path.c_str(), nullptr, mbedtls_ctr_drbg_random,
                                               &get_mbedtls_global().ctr_drbg);
      if (ret != 0)
        return fail("failed to parse private key '{}': {}", path, ret);

      return Result<void>();
    }

    auto configure_tls_context(TlsContextImpl &impl, const TlsConfig &config, bool is_server) -> Result<void>
    {
      impl.is_server = is_server;

      const int endpoint = is_server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT;
      int ret = mbedtls_ssl_config_defaults(&impl.conf, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM,
                                            MBEDTLS_SSL_PRESET_DEFAULT);
      if (ret != 0)
        return fail("mbedtls_ssl_config_defaults failed: {}", ret);

      mbedtls_ssl_conf_rng(&impl.conf, mbedtls_ctr_drbg_random, &get_mbedtls_global().ctr_drbg);

      if (is_server)
      {
        mbedtls_ssl_conf_authmode(&impl.conf, MBEDTLS_SSL_VERIFY_NONE);

        if (config.cert_file.empty() || config.key_file.empty())
          return fail("server TLS requires cert_file and key_file");

        AU_TRY_DISCARD(load_pem_cert(impl.own_cert, config.cert_file));
        AU_TRY_DISCARD(load_pem_key(impl.own_key, config.key_file));
        mbedtls_ssl_conf_own_cert(&impl.conf, &impl.own_cert, &impl.own_key);

        if (!config.ca_file.empty() && config.verify_mode == ETlsVerifyMode::Required)
        {
          AU_TRY_DISCARD(load_pem_cert(impl.ca_chain, config.ca_file));
          mbedtls_ssl_conf_ca_chain(&impl.conf, &impl.ca_chain, nullptr);
          mbedtls_ssl_conf_authmode(&impl.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        }
      }
      else
      {
        const int verify = config.verify_mode == ETlsVerifyMode::Required ? MBEDTLS_SSL_VERIFY_REQUIRED
                                                                          : MBEDTLS_SSL_VERIFY_NONE;
        mbedtls_ssl_conf_authmode(&impl.conf, verify);

        if (config.verify_mode == ETlsVerifyMode::Required)
        {
          if (config.ca_file.empty())
            return fail("client TLS verification requires ca_file");

          AU_TRY_DISCARD(load_pem_cert(impl.ca_chain, config.ca_file));
          mbedtls_ssl_conf_ca_chain(&impl.conf, &impl.ca_chain, nullptr);
        }

        if (!config.cert_file.empty() && !config.key_file.empty())
        {
          AU_TRY_DISCARD(load_pem_cert(impl.own_cert, config.cert_file));
          AU_TRY_DISCARD(load_pem_key(impl.own_key, config.key_file));
          mbedtls_ssl_conf_own_cert(&impl.conf, &impl.own_cert, &impl.own_key);
        }
      }

      return Result<void>();
    }
  } // namespace

  TlsContext_T::~TlsContext_T()
  {
    delete static_cast<TlsContextImpl *>(impl);
    impl = nullptr;
  }

  auto __tls_context_impl(TlsContext &tls) -> void *
  {
    return tls->impl;
  }

  auto __tls_context_is_server(TlsContext &tls) -> bool
  {
    auto *impl = static_cast<TlsContextImpl *>(tls->impl);
    return impl != nullptr && impl->is_server;
  }

  auto __setup_tls_session(NativeSocket *sock, TlsContext &tls, const char *hostname) -> Result<void *>
  {
    auto *impl = static_cast<TlsContextImpl *>(__tls_context_impl(tls));
    if (impl == nullptr)
      return fail("invalid TLS context");

    return setup_tls_session(sock, *impl, hostname);
  }

  auto create_tls_server_context(const TlsConfig &config) -> Result<TlsContext>
  {
    auto ctx = make_box<TlsContext_T>();
    auto *impl = new TlsContextImpl();
    ctx->impl = impl;

    auto cfg_r = configure_tls_context(*impl, config, true);
    if (cfg_r.is_err())
    {
      delete impl;
      ctx->impl = nullptr;
      return fail("{}", cfg_r.error());
    }

    return ctx;
  }

  auto create_tls_client_context(const TlsConfig &config) -> Result<TlsContext>
  {
    auto ctx = make_box<TlsContext_T>();
    auto *impl = new TlsContextImpl();
    ctx->impl = impl;

    auto cfg_r = configure_tls_context(*impl, config, false);
    if (cfg_r.is_err())
    {
      delete impl;
      ctx->impl = nullptr;
      return fail("{}", cfg_r.error());
    }

    return ctx;
  }

  auto tls_client_connect(SocketClient &client, const String &address, u16 port, TlsContext &tls) -> Result<Connection>
  {
    if (__tls_context_is_server(tls))
      return fail("TLS context is configured for server use");

    auto conn_r = socket_client_connect(client, address, port);
    if (conn_r.is_err())
      return fail("failed to connect: {}", conn_r.error());

    auto conn = std::move(conn_r.unwrap());

    auto session_r = __setup_tls_session(&conn->sock, tls, address.c_str());
    if (session_r.is_err())
      return fail("{}", session_r.error());

    conn->tls = session_r.unwrap();
    return conn;
  }

  auto tls_server_accept(SocketServer &server, TlsContext &tls) -> Result<Connection>
  {
    if (!__tls_context_is_server(tls))
      return fail("TLS context is configured for client use");

    auto conn_r = socket_server_accept(server);
    if (conn_r.is_err())
      return fail("failed to accept connection: {}", conn_r.error());

    auto conn = std::move(conn_r.unwrap());

    auto session_r = __setup_tls_session(&conn->sock, tls, nullptr);
    if (session_r.is_err())
      return fail("{}", session_r.error());

    conn->tls = session_r.unwrap();
    return conn;
  }
} // namespace ianet
