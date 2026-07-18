module;

#include "private/crypto_tls.hpp"

#include <openssl/aead.h>
#include <openssl/hkdf.h>
#include <openssl/mem.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>

module ianet.crypto;

namespace ianet::crypto
{
  namespace
  {
    // ChaCha20-Poly1305: 12-byte nonce, 16-byte tag, 32-byte key.
    constexpr std::size_t INNER_NONCE_SIZE = 12U;
    constexpr std::size_t INNER_KEY_SIZE = 32U;      // 256-bit ChaCha20 key
    constexpr std::size_t INNER_EXPORTER_SIZE = 64U; // HKDF-Extract salt
    constexpr std::size_t INNER_PRK_SIZE = 32U;      // SHA-256 output

    // Exporter label is fixed for this profile; both peers must agree on it and
    // on the empty (used, zero-length) context. See docs/PROTOCOL.md.
    constexpr char EXPORTER_LABEL[] = "EXPORTER-iatunnel-inner-v1";
    constexpr char INFO_C2S[] = "iatunnel inner c2s";
    constexpr char INFO_S2C[] = "iatunnel inner s2c";

    // Fixed, cause-agnostic authentication error (D9): never distinguishes
    // tamper from desync from wrong-PSK, and carries no secret-derived data.
    constexpr char INNER_AUTH_ERROR[] = "inner PSK authentication failed";

    struct InnerSealerState
    {
      // seal_ctx uses this endpoint's send key; open_ctx its receive key.
      EVP_AEAD_CTX *seal_ctx{};
      EVP_AEAD_CTX *open_ctx{};

      ~InnerSealerState()
      {
        EVP_AEAD_CTX_free(seal_ctx);
        EVP_AEAD_CTX_free(open_ctx);
      }
    };

    auto session_native(TlsSession &session) -> SSL *
    {
      if (!session)
        return nullptr;
      auto *impl = static_cast<detail::Session *>(session->impl);
      return impl != nullptr ? impl->native.get() : nullptr;
    }

    auto session_ready(TlsSession &session) -> bool
    {
      if (!session)
        return false;
      auto *impl = static_cast<detail::Session *>(session->impl);
      return impl != nullptr && impl->native && impl->authenticated;
    }

    // nonce = 0x00000000 || sequence (big-endian) — high 4 bytes always zero.
    auto build_nonce(u64 sequence) -> std::array<std::uint8_t, INNER_NONCE_SIZE>
    {
      std::array<std::uint8_t, INNER_NONCE_SIZE> nonce{};
      for (std::size_t i = 0; i < 8U; ++i)
        nonce[INNER_NONCE_SIZE - 1U - i] = static_cast<std::uint8_t>((sequence >> (8U * i)) & 0xFFU);
      return nonce;
    }

    auto sealer_state(InnerSealer &sealer) -> InnerSealerState *
    {
      return sealer ? static_cast<InnerSealerState *>(sealer->impl) : nullptr;
    }
  } // namespace

  InnerSealer_T::~InnerSealer_T()
  {
    delete static_cast<InnerSealerState *>(impl);
    impl = nullptr;
  }

  auto create_inner_sealer(TlsSession &session, Span<const u8> psk, InnerDirection seal_direction) -> Result<InnerSealer>
  {
    if (!session_ready(session))
      return fail("inner sealer requires a completed, authenticated TLS session");
    if (psk.size() != INNER_PSK_SIZE)
      return fail("inner PSK must be exactly {} bytes", INNER_PSK_SIZE);

    SSL *ssl = session_native(session);
    if (ssl == nullptr)
      return fail("inner sealer could not access the TLS session");

    // Secret material lives only on this stack frame and in the AEAD contexts;
    // all of it is wiped before returning, on every path.
    std::array<std::uint8_t, INNER_EXPORTER_SIZE> exporter{};
    std::array<std::uint8_t, INNER_PRK_SIZE> prk{};
    std::array<std::uint8_t, INNER_KEY_SIZE> key_c2s{};
    std::array<std::uint8_t, INNER_KEY_SIZE> key_s2c{};

    const auto wipe_all = [&]() {
      OPENSSL_cleanse(exporter.data(), exporter.size());
      OPENSSL_cleanse(prk.data(), prk.size());
      OPENSSL_cleanse(key_c2s.data(), key_c2s.size());
      OPENSSL_cleanse(key_s2c.data(), key_s2c.size());
    };

    // RFC 8446 s7.5 exporter, empty context (use_context = 1, length 0).
    if (SSL_export_keying_material(ssl, exporter.data(), exporter.size(), EXPORTER_LABEL,
                                   sizeof(EXPORTER_LABEL) - 1U, nullptr, 0U, 1) != 1)
    {
      wipe_all();
      return fail("inner sealer key export failed");
    }

    std::size_t prk_len = prk.size();
    if (HKDF_extract(prk.data(), &prk_len, EVP_sha256(), psk.data(), psk.size(), exporter.data(), exporter.size()) != 1 ||
        prk_len != prk.size())
    {
      wipe_all();
      return fail("inner sealer key derivation failed");
    }

    if (HKDF_expand(key_c2s.data(), key_c2s.size(), EVP_sha256(), prk.data(), prk.size(),
                    reinterpret_cast<const std::uint8_t *>(INFO_C2S), sizeof(INFO_C2S) - 1U) != 1 ||
        HKDF_expand(key_s2c.data(), key_s2c.size(), EVP_sha256(), prk.data(), prk.size(),
                    reinterpret_cast<const std::uint8_t *>(INFO_S2C), sizeof(INFO_S2C) - 1U) != 1)
    {
      wipe_all();
      return fail("inner sealer key derivation failed");
    }

    const bool client = seal_direction == InnerDirection::client_to_server;
    const auto &seal_key = client ? key_c2s : key_s2c;
    const auto &open_key = client ? key_s2c : key_c2s;

    auto state = std::unique_ptr<InnerSealerState>(new (std::nothrow) InnerSealerState());
    if (!state)
    {
      wipe_all();
      return fail("allocate inner sealer failed");
    }

    const EVP_AEAD *aead = EVP_aead_chacha20_poly1305();
    state->seal_ctx = EVP_AEAD_CTX_new(aead, seal_key.data(), seal_key.size(), EVP_AEAD_DEFAULT_TAG_LENGTH);
    state->open_ctx = EVP_AEAD_CTX_new(aead, open_key.data(), open_key.size(), EVP_AEAD_DEFAULT_TAG_LENGTH);
    wipe_all();
    if (state->seal_ctx == nullptr || state->open_ctx == nullptr)
      return fail("inner sealer cipher initialization failed");

    auto sealer = make_box<InnerSealer_T>();
    sealer->impl = state.release();
    return sealer;
  }

  auto inner_seal(InnerSealer &sealer, u64 sequence, Span<const u8> aad, Span<const u8> plaintext) -> Result<Vec<u8>>
  {
    auto *state = sealer_state(sealer);
    if (state == nullptr || state->seal_ctx == nullptr)
      return fail("inner sealer is not initialized");
    if (plaintext.size() > std::numeric_limits<std::size_t>::max() - INNER_SEAL_OVERHEAD_SIZE)
      return fail("inner seal plaintext is too large");

    const auto nonce = build_nonce(sequence);
    Vec<u8> sealed(plaintext.size() + INNER_SEAL_OVERHEAD_SIZE);
    std::size_t sealed_len = 0U;
    if (EVP_AEAD_CTX_seal(state->seal_ctx, sealed.data(), &sealed_len, sealed.size(), nonce.data(), nonce.size(),
                          plaintext.data(), plaintext.size(), aad.data(), aad.size()) != 1)
      return fail("inner seal failed");
    sealed.resize(sealed_len);
    return sealed;
  }

  auto inner_open(InnerSealer &sealer, u64 sequence, Span<const u8> aad, Span<const u8> sealed) -> Result<Vec<u8>>
  {
    auto *state = sealer_state(sealer);
    if (state == nullptr || state->open_ctx == nullptr)
      return fail("inner sealer is not initialized");
    if (sealed.size() < INNER_SEAL_OVERHEAD_SIZE)
      return fail("{}", INNER_AUTH_ERROR);

    const auto nonce = build_nonce(sequence);
    Vec<u8> plaintext(sealed.size() - INNER_SEAL_OVERHEAD_SIZE);
    std::size_t plaintext_len = 0U;
    if (EVP_AEAD_CTX_open(state->open_ctx, plaintext.data(), &plaintext_len, plaintext.size(), nonce.data(),
                          nonce.size(), sealed.data(), sealed.size(), aad.data(), aad.size()) != 1)
    {
      // No plaintext is released on authentication failure; wipe the scratch
      // buffer regardless and return the fixed, cause-agnostic error.
      OPENSSL_cleanse(plaintext.data(), plaintext.size());
      return fail("{}", INNER_AUTH_ERROR);
    }
    plaintext.resize(plaintext_len);
    return plaintext;
  }

  auto secure_erase(Span<u8> bytes) -> void
  {
    if (!bytes.empty())
      OPENSSL_cleanse(bytes.data(), bytes.size());
  }
} // namespace ianet::crypto
