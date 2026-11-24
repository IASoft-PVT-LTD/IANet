# IANet

IANet exposes its socket APIs through `import ianet`, a socket-attached TLS API
through `import ianet.tls`, and a provider-neutral memory-BIO crypto API through
`import ianet.crypto`. AWS-LC is the sole TLS provider; `ianet.tls` adapts the
memory-BIO API to sockets while public modules expose only opaque handles,
Auxid containers, state enums, and `Result<T>` diagnostics.

Cross-platform C++20 networking library for Windows and Linux. IANet provides
socket clients and servers, HTTP/1.x, TLS (via AWS-LC), and HTTPS helpers on
top of the [Auxid](https://github.com/IASoft-PVT-LTD/Auxid) platform library.

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
- C++20 compiler with module support (MSVC or Clang)
- [LibAuxid](https://github.com/IASoft-PVT-LTD/Auxid) (included as submodule)
- Doxygen 1.9.8+ on `PATH` when building API reference (1.11+ recommended)

## Quick start (CMake)

Integrate IANet with CMake `FetchContent`:

```cmake
cmake_minimum_required(VERSION 3.28)
project(my_app CXX)

include(FetchContent)

FetchContent_Declare(
  IANet
  GIT_REPOSITORY https://github.com/IASoft-PVT-LTD/IANet.git
  GIT_TAG        main  # pin a commit
)
FetchContent_MakeAvailable(IANet)

auxid_setup_project()

add_executable(my_app main.cpp)
set_target_properties(my_app PROPERTIES CXX_SCAN_FOR_MODULES ON)
target_link_libraries(my_app PRIVATE IANET)
```

### Example

```cpp
#include <auxid/macros.hpp>

#include <utility>

import ianet;

using namespace au;

auto say_hello() -> Result<usize>
{
  AU_TRY_VAR(ctx, ianet::create_context());
  AU_TRY_VAR(client, ianet::create_socket_client(ctx, ianet::EProtocolType::TCP));
  AU_TRY_VAR(conn, ianet::socket_client_connect(client, String("127.0.0.1"), 8080));

  const u8 msg[] = {'h', 'e', 'l', 'l', 'o'};
  AU_TRY_DISCARD(ianet::connection_send(conn, Span<const u8>(msg)));

  AU_TRY_VAR(reply, ianet::connection_receive(conn, 1024));
  return reply.size();
}

auto main() -> int
{
  auxid::MainThreadGuard guard;
  Logger &log = auxid::get_thread_logger();

  auto received = say_hello();
  if (received.is_err())
  {
    log.error("{}", received.unwrap_err().describe());
    return 1;
  }
  log.info("received {} bytes", received.unwrap());
  return 0;
}
```

## API reference

Browse the generated API pages from the navigation bar, or start with:

- [API overview](ianet/links.md)
- [ianet namespace](ianet/namespaceianet.md)

## License

Copyright © 2026 IASoft (PVT) LTD. Licensed under the
[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
