# SPDX-License-Identifier: GPL-3.0-or-later
mcxanon_add_module(pseudo
  SOURCES category.cpp hmac.cpp ranges.cpp special_addresses.cpp mapping.cpp atomic_file.cpp
          datadir.cpp lock.cpp project.cpp pseudonymiser.cpp fsutil.cpp crypto.cpp prefix_preserving.cpp
          text_formats.cpp
  DEPS bytes
  EXTERNAL OpenSSL::Crypto nlohmann_json::nlohmann_json)
