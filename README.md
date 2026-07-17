<div align="center">
  <img src="logo.png" alt="IANet Logo" width="190" style="padding-bottom: 8px;"/>
  <br/>

  <img src="https://img.shields.io/badge/platform-Win64 | Linux-darkred.svg" alt="Platform"/>
  <img src="https://img.shields.io/badge/compiler-MSVC | Clang | GCC-darkgreen.svg" alt="Compiler"/>

  <p style="padding-top: 0.2rem;">
    <b>IANet: Cross-Platform Networking Library for C++</b>
  </p>
</div>

> [!NOTE]
> IANet has been migrated to a module-only API.
>
> If you're a current license holder, you should have received an email from IASoft detailing the changes, alongside a full migration guide, a repository link for header-only API security updates and a rationale for this decision.
>
> If you have (or previously held) a license to this library but didn't recieve the email, please raise a support ticket through IASoft Client Dashboard!

### Core features

- **Cross-Platform:** Seamlessly supports both Windows (Winsock2) and Linux (POSIX sockets).
- **Simple API:** Easy-to-use functions for managing contexts, clients, servers, and connections.
- **Robust Error Handling:** Utilizes `Result<T>` for safe, exception-free error management.
- **Modern C++:** Built with modern C++ practices, custom allocators, and smart pointers.
- **Crypto Abstraction:** `ianet.crypto` provides memory-BIO TLS contexts and
  sessions backed by AWS-LC without exposing provider-native types.
  `ianet.tls` and HTTPS use the same backend through a socket adapter.

## Quick start (CMake)

You can easily integrate IANet into your project using CMake's `FetchContent`:

```cmake
include(FetchContent)

FetchContent_Declare(
    IANET
    GIT_REPOSITORY https://github.com/IASoft-PVT-LTD/IANet
    GIT_TAG        main
)
FetchContent_MakeAvailable(IANET)

# Link against your target
target_link_libraries(your_target PRIVATE IANET)
```

### Example

Here is a simple example demonstrating how to create a client, connect to a server, and send/receive data:

```cpp
#include <utility>

#include <auxid/macros.hpp>

import ianet;

using namespace au;

auto app_main() -> Result<void>
{
  // Create a networking context
  auto ctx = AU_TRY(ianet::create_context());

  // Create a client
  auto client = AU_TRY(ianet::create_socket_client(ctx, ianet::EProtocolType::TCP));

  // Connect to a local server on port 8080
  auto conn = AU_TRY(ianet::socket_client_connect(client, String("127.0.0.1"), 8080));

  // Send a message
  const u8 msg[] = {'h', 'e', 'l', 'l', 'o'};
  AU_TRY(ianet::connection_send(conn, Span<const u8>(msg, sizeof(msg))));

  // Receive a reply (up to 1024 bytes)
  auto reply = AU_TRY(ianet::connection_receive(conn, 1024));

  return {};
}

int main(int argc, char *argv[])
{
  // Initialize the Auxid platform main thread
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

## Documentation

Find the documentation at [https://docs.iasoft.dev/ianet](https://docs.iasoft.dev/ianet)

Output is written to `docs/site/`.

## License

Copyright © 2026 IASoft (PVT) LTD. Licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0).
