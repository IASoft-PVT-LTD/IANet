// IANet: Cross-Platform Networking Library for C++
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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