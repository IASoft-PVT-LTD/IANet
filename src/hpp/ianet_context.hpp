// IANet: Cross-Platform Networking Library for C++
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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