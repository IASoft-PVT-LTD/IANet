# IANet

IANet exposes its socket APIs through `import ianet`, its existing
socket-attached TLS API through `import ianet.tls`, and an additive
provider-neutral memory-BIO crypto API through `import ianet.crypto`.
`ianet.crypto` is backed by AWS-LC but exports only opaque handles, Auxid
containers, state enums, and `Result<T>` diagnostics.

Cross-platform C++23 networking library for Windows and Linux. IANet provides
socket clients and servers, HTTP/1.x, TLS (via MbedTLS), and HTTPS helpers on
top of the [Auxid](https://github.com/IASoft-PVT-LTD/libauxid) platform library.

## Module map

| Module | Import | Purpose |
|--------|--------|---------|
| Core | `import ianet;` | Sockets, connections, re-exports `auxid` |
| HTTP | `import ianet.http;` | HTTP/1.x client and server |
| TLS | `import ianet.tls;` | TLS contexts and encrypted connections |
| Crypto | `import ianet.crypto;` | Provider-neutral memory-BIO TLS primitives |
| HTTPS | `import ianet.https;` | Convenience HTTPS server/client helpers |

```
ianet
 ├── ianet.http ──► ianet.https
 ├── ianet.tls  ──► ianet.https
 └── ianet.crypto
```

The core `ianet` module **re-exports Auxid** (`export import auxid`). Use Auxid
types such as `Result<T>`, `String`, and `MainThreadGuard` in your application.

## Requirements

- CMake 3.28+
- C++23 compiler with module support (MSVC, Clang, GCC)
- [LibAuxid](https://github.com/IASoft-PVT-LTD/libauxid) (included as submodule)
- Doxygen 1.9.8+ on `PATH` when building API reference (1.11+ recommended)

## Quick start (CMake)

Integrate IANet with CMake `FetchContent`:

```cmake
include(FetchContent)

FetchContent_Declare(
    IANET
    GIT_REPOSITORY https://github.com/IASoft-PVT-LTD/IANet
    GIT_TAG        main
)
FetchContent_MakeAvailable(IANET)

target_link_libraries(your_target PRIVATE IANET)
```

### Example

```cpp
#include <auxid/macros.hpp>

import ianet;

using namespace au;

auto app_main() -> Result<void>
{
  auto ctx = AU_TRY(ianet::create_context());
  auto client = AU_TRY(ianet::create_socket_client(ctx, ianet::EProtocolType::TCP));
  auto conn = AU_TRY(ianet::socket_client_connect(client, String("127.0.0.1"), 8080));

  const u8 msg[] = {'h', 'e', 'l', 'l', 'o'};
  AU_TRY(ianet::connection_send(conn, Span<const u8>(msg, sizeof(msg))));

  auto reply = AU_TRY(ianet::connection_receive(conn, 1024));
  return {};
}

int main(int argc, char *argv[])
{
  auxid::MainThreadGuard _main_thread_guard;

  const auto result = app_main();
  if (!result)
  {
    auxid::get_thread_logger().error("Application failed with error: %s", result.error().c_str());
    return 1;
  }

  return 0;
}
```

## API reference

Browse the generated API pages from the navigation bar, or start with:

- [API overview](ianet/links.md)
- [ianet namespace](ianet/namespaceianet.md)

## License

Copyright © 2026 IASoft (PVT) LTD. Licensed under the
[PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0).
