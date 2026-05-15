// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the PolyForm Noncommercial License 1.0.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://polyformproject.org/licenses/noncommercial/1.0.0>.

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
