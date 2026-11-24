<div align="center">
  <img src="logo.png" alt="IANet Logo" width="190" style="padding-bottom: 8px;"/>
  <br/>

  <img src="https://img.shields.io/badge/license-Apache_2.0-darkblue.svg" alt="License"/>
  <img src="https://img.shields.io/badge/standard-C%2B%2B20-darkred.svg" alt="C++ Standard"/>
  <img src="https://img.shields.io/badge/compiler-MSVC | Clang-darkgreen.svg" alt="Compiler"/>
  <img src="https://img.shields.io/badge/platforms-Linux | Windows-darkslateblue.svg" alt="Platforms"/>

  <p style="padding-top: 0.2rem;">
    <b>IANet: Cross-Platform Networking Library for C++</b>
  </p>
</div>

IANet is a C++20 networking library with TCP and UDP sockets, HTTP/1.x and TLS 1.3. It has no headers to include; you `import ianet;` and the modules you need. Calls that can fail return an [Auxid](https://github.com/IASoft-PVT-LTD/Auxid) `Result<T>`, and nothing throws.

## Quick start

You need CMake 3.28 or newer and Clang or MSVC. GCC 15.2 doesn't build IANet yet.

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

`main.cpp`, which sends five bytes to a local server and waits for a reply:

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

IANet and everything linked into it use Auxid's compile flags: no exceptions and no RTTI. They must also share one C++ standard. The default is C++20, so set `CMAKE_CXX_STANDARD` before `FetchContent_MakeAvailable` if you want a newer one. `auxid_setup_project()` turns CMake's module scanning off, which is why the target turns it back on.

## Modules

| Module | Contents |
| --- | --- |
| [`ianet`](src/modules/ianet.cppm) | TCP and UDP sockets. Also exports `auxid` |
| [`ianet.http`](src/modules/ianet.http.cppm) | HTTP/1.x client and server |
| [`ianet.tls`](src/modules/ianet.tls.cppm) | TLS over a socket |
| [`ianet.https`](src/modules/ianet.https.cppm) | HTTP over TLS |
| [`ianet.crypto`](src/modules/ianet.crypto.cppm) | TLS without a socket: you move the ciphertext yourself |

A TLS connection is the same `Connection` type as a plain one, so `connection_send` and `connection_receive` work on both.

### TLS

The TLS code runs on [AWS-LC](https://github.com/aws/aws-lc), whose types never appear in the public API. Only TLS 1.3 is accepted, with `TLS_CHACHA20_POLY1305_SHA256`. The key exchange prefers the post-quantum hybrid X25519MLKEM768 and falls back to X25519 or P-256.

Clients check the server's certificate and name unless you turn verification off. Names are matched against the subject alternative names only, and wildcards are off until you set `allow_wildcard_peer_names`. Session resumption and early data are disabled.

### Limits

- Addresses are IPv4 strings. There is no DNS lookup.
- Servers listen on all interfaces.
- Sockets block. `connection_wait_readable` and `connection_wait_writable` take a timeout, and so does one overload of `socket_client_connect`.

The API reference is at [docs.iasoft.dev/ianet](https://docs.iasoft.dev/ianet).

## Building and testing

```bash
git clone --recursive https://github.com/IASoft-PVT-LTD/IANet.git
cd IANet
cmake --preset IANet-x64-linux
cmake --build --preset IANet-x64-linux --config Release
ctest --preset IANet-x64-linux --output-on-failure
```

[CI](.github/workflows/ci.yaml) runs on every push and pull request to `main`. It builds and tests with Clang on Linux x64 and MSVC on Windows x64, both at C++20 and C++23, and runs the tests under ASan, UBSan and TSan on Linux. [CMakePresets.json](CMakePresets.json) has presets for more targets that CI doesn't cover.

## Who wrote what

[AI-Human-Map.md](AI-Human-Map.md) records which parts of IANet were written by people and which by AI, with the model named for each part. Run `python3 tools/authorship_map.py` when you change the code. CI checks it.

## License

Copyright © 2026 IASoft (PVT) LTD. Licensed under the [Apache License, Version 2.0](LICENSE).

The vendored [picohttpparser](https://github.com/h2o/picohttpparser) keeps its own license, recorded in its source files. AWS-LC is downloaded at configure time and has [its own license](https://github.com/aws/aws-lc/blob/main/LICENSE). The certificates and keys in `tests/fixtures` exist only for the tests.
