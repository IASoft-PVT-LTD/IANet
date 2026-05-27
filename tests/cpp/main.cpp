// IANet: Cross-Platform Networking Library for C++
//
// Copyright (C) 2026 I-A-S (ias@iasoft.dev)
// Copyright (C) 2026 IASoft (PVT) LTD (contact@iasoft.dev)
//
// This source code is licensed under the PolyForm Noncommercial License 1.0.0.
// A copy of this license is included in the LICENSE file at the root of this project,
// and is also available at <https://polyformproject.org/licenses/noncommercial/1.0.0>.

#include <iostream>

#include <auxid/macros.hpp>

import auxid;
import auxid.test;

using namespace au;

int main(int argc, char *argv[])
{
  AU_UNUSED(argc);
  AU_UNUSED(argv);

  auxid::MainThreadGuard _main_thread_guard;

  std::cout << console::GREEN << "\n================================\n";
  std::cout << "   ianet - Unit Test Suite\n";
  std::cout << "================================\n" << console::RESET << "\n";

  return test::TestRegistry::run_all();
}
