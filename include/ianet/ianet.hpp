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
