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
> IAUSB has been migrated to a module-only API.
>
> If you're a current license holder, you should have received an email from IASoft detailing the changes, alongside a full migration guide, a repository link for header-only API security updates and a rationale for this decision.
>
> If you have (or previously held) a license to this library but didn't recieve the email, please raise a support ticket through IASoft Client Dashboard!

### Core features

- **Cross-Platform:** Seamlessly supports both Windows (Winsock2) and Linux (POSIX sockets).
- **Simple API:** Easy-to-use functions for managing contexts, clients, servers, and connections.
- **Robust Error Handling:** Utilizes `Result<T>` for safe, exception-free error management.
- **Modern C++:** C++23 modules (`import ianet` / `import ianet.http`), built on [Auxid](https://github.com/I-A-S/Auxid).

## Quick start (CMake)

You can easily integrate IANet into your project using CMake's `FetchContent`:

```cmake
cmake_minimum_required(VERSION 3.28)
project(my_app CXX)

include(FetchContent)
FetchContent_Declare(
    ianet
    GIT_REPOSITORY https://github.com/I-A-S/ianet.git
    GIT_TAG        main # Or a specific release tag
)
FetchContent_MakeAvailable(ianet)

add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE IANET)
set_target_properties(my_app PROPERTIES CXX_SCAN_FOR_MODULES ON)
```

Requires C++23, CMake 3.28+, and a supported compiler (Clang, MSVC, or GCC 15.2+ via Auxid).

### Example

Socket-only consumers use `import ianet;`. HTTP clients use `import ianet.http;` (re-exports `ianet` and Auxid).

```cpp
import ianet.http;

using namespace au;
using namespace ianet;

auto app_main() -> Result<void>
{
  auto ctx = AU_TRY(create_context());
  auto client = AU_TRY(create_socket_client(ctx, EProtocolType::TCP));
  auto conn = AU_TRY(socket_client_connect(client, String("127.0.0.1"), 8080));

  const u8 msg[] = {'h', 'e', 'l', 'l', 'o'};
  AU_TRY(connection_send(conn, Span<const u8>(msg, sizeof(msg))));

  auto reply = AU_TRY(connection_receive(conn, 1024));
  (void) reply;

  return {};
}

int main(int argc, char *argv[])
{
  AU_UNUSED(argc);
  AU_UNUSED(argv);

  auxid::MainThreadGuard _main_thread_guard;

  const auto result = app_main();
  if (!result)
  {
    auxid::get_thread_logger().error("Application failed with error: {}", result.error());
    return 1;
  }

  return 0;
}
```

## License

Copyright © 2026 IASoft (PVT) LTD. Licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0).
