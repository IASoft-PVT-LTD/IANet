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

#include <ianet_context.hpp>

namespace ianet
{
  auto create_context() -> Result<Context>
  {
    return Context_T::create();
  }

  auto Context_T::create() -> Result<Context>
  {
    HeapAllocator alloc;
    void *mem = alloc.alloc(sizeof(Context_T), alignof(Context_T));
    if (!mem)
      return fail("failed to allocate context");

    const auto context = new (mem) Context_T();
#if AU_PLATFORM_WINDOWS
    WSAData wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
      return fail("failed to initialize WSA: '%s'", WSAGetLastError());
#endif

    return Box<Context_T, Deleter_Context_T<HeapAllocator>>(context, Deleter_Context_T<HeapAllocator>(alloc));
  }

  auto __internal_destory_context(HeapAllocator *allocator, Context_T *context) -> void
  {
    if (!context)
      return;

#if AU_PLATFORM_WINDOWS
    WSACleanup();
#endif

    context->~Context_T();
    allocator->free(context, sizeof(Context_T), alignof(Context_T));
  }
} // namespace ianet
