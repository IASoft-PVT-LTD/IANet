// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the PolyForm Noncommercial License 1.0.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://polyformproject.org/licenses/noncommercial/1.0.0>.

#pragma once

#include <ianet/definitions.hpp>

namespace ianet
{
  using Context = Box<Context_T, Deleter_Context_T<HeapAllocator>>;
  using Client = Box<Client_T, Deleter_Client_T<HeapAllocator>>;
  using Server = Box<Server_T, Deleter_Server_T<HeapAllocator>>;
  using Connection = Box<Connection_T, Deleter_Connection_T<HeapAllocator>>;

  auto create_context() -> Result<Context>;

  auto create_client(Context &ctx) -> Result<Client>;
  auto create_server(Context &ctx, u16 port) -> Result<Server>;

  auto client_connect(Client &client, const String &address, u16 port) -> Result<Connection>;
  auto server_accept(Server &server) -> Result<Connection>;

  auto connection_send(Connection &connection, Span<const u8> data) -> Result<void>;
  auto connection_receive(Connection &connection, usize size) -> Result<Vec<u8>>;
} // namespace ianet
