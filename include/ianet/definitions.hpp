// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the PolyForm Noncommercial License 1.0.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://polyformproject.org/licenses/noncommercial/1.0.0>.

#pragma once

#include <auxid/auxid.hpp>
#include <auxid/containers/pair.hpp>
#include <auxid/containers/string.hpp>
#include <auxid/containers/vec.hpp>
#include <auxid/memory/box.hpp>

namespace ianet
{
  using namespace au;
  using namespace au::memory;

  enum class EProtocolType
  {
    TCP = 0,
    UDP = 1,
  };

  struct Context_T;
  struct SocketClient_T;
  struct SocketServer_T;
  struct Connection_T;
  struct HttpClient_T;
  struct HttpServer_T;
  struct HttpConnection_T;

  struct HttpRequest
  {
    String method;
    String path;
    int minor_version;
    Vec<Pair<String, String>> headers;
    Vec<u8> body;
  };

  struct HttpResponse
  {
    int minor_version;
    u16 status_code;
    String status_message;
    Vec<Pair<String, String>> headers;
    Vec<u8> body;
  };

  auto __internal_destory_context(HeapAllocator *allocator, Context_T *context) -> void;
  auto __internal_destory_client(HeapAllocator *allocator, SocketClient_T *client) -> void;
  auto __internal_destory_server(HeapAllocator *allocator, SocketServer_T *server) -> void;
  auto __internal_destory_connection(HeapAllocator *allocator, Connection_T *connection) -> void;
  auto __internal_destory_http_client(HeapAllocator *allocator, HttpClient_T *client) -> void;
  auto __internal_destory_http_server(HeapAllocator *allocator, HttpServer_T *server) -> void;
  auto __internal_destory_http_connection(HeapAllocator *allocator, HttpConnection_T *connection) -> void;

  AU_DECLARE_CUSTOM_DELETER(Context_T, __internal_destory_context);
  AU_DECLARE_CUSTOM_DELETER(SocketClient_T, __internal_destory_client);
  AU_DECLARE_CUSTOM_DELETER(SocketServer_T, __internal_destory_server);
  AU_DECLARE_CUSTOM_DELETER(Connection_T, __internal_destory_connection);
  AU_DECLARE_CUSTOM_DELETER(HttpClient_T, __internal_destory_http_client);
  AU_DECLARE_CUSTOM_DELETER(HttpServer_T, __internal_destory_http_server);
  AU_DECLARE_CUSTOM_DELETER(HttpConnection_T, __internal_destory_http_connection);
} // namespace ianet
