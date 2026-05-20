<div align="center">
  <img src="logo.png" alt="IANet Logo" width="190" style="padding-bottom: 8px;"/>
  <br/>

  <img src="https://img.shields.io/badge/platform-Win64 | Linux-darkred.svg" alt="Platform"/>
  <img src="https://img.shields.io/badge/compiler-MSVC | Clang-darkgreen.svg" alt="Compiler"/>

  <p style="padding-top: 0.2rem;">
    <b>IANet: Cross-Platform Networking Library for C++</b>
  </p>
</div>

### Core features

- **Cross-Platform:** Seamlessly supports both Windows (Winsock2) and Linux (POSIX sockets).
- **Simple API:** Easy-to-use functions for managing contexts, clients, servers, and connections.
- **Robust Error Handling:** Utilizes `Result<T>` for safe, exception-free error management.
- **Modern C++:** Built with modern C++ practices, custom allocators, and smart pointers.

## Quick start (CMake)

You can easily integrate IANet into your project using CMake's `FetchContent`:

```cmake
include(FetchContent)

FetchContent_Declare(
    ianet
    GIT_REPOSITORY https://github.com/I-A-S/ianet.git
    GIT_TAG        main # Or a specific release tag
)
FetchContent_MakeAvailable(ianet)

# Link against your target
target_link_libraries(your_target PRIVATE ianet)
```

### Example

Here is a simple example demonstrating how to create a client, connect to a server, and send/receive data:

```cpp
#include <ianet/ianet.hpp>
#include <auxid/core/main_thread.hpp>
#include <auxid/core/logger.hpp>

using namespace au;

auto app_main() -> Result<void>
{
  // Create a networking context
  auto ctx = AU_TRY(ianet::create_context());

  // Create a client
  auto client = AU_TRY(ianet::create_socket_client(ctx));

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

## License

Copyright © 2026 IASoft (PVT) LTD. Licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0).
