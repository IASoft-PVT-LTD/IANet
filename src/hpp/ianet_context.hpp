// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the PolyForm Noncommercial License 1.0.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://polyformproject.org/licenses/noncommercial/1.0.0>.

#pragma once

#include <ianet/ianet.hpp>

#if AU_PLATFORM_WINDOWS
#  define NOMINMAX
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
#elif AU_PLATFORM_LINUX
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

namespace ianet
{
#if AU_PLATFORM_WINDOWS
  using NativeSocket = SOCKET;
#else
  using NativeSocket = int;
#endif

  [[nodiscard]] inline auto native_socket_valid(NativeSocket s) -> bool
  {
#if AU_PLATFORM_WINDOWS
    return s != INVALID_SOCKET;
#else
    return s >= 0;
#endif
  }

  inline auto native_socket_close(NativeSocket s) -> void
  {
#if AU_PLATFORM_WINDOWS
    if (s != INVALID_SOCKET)
      closesocket(s);
#else
    if (s >= 0)
      ::close(s);
#endif
  }

  struct Context_T
  {

public:
    static auto create() -> Result<Context>;
  };
} // namespace ianet