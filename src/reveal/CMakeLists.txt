# SPDX-License-Identifier: GPL-3.0-or-later
#
# Reveal (feature 006): maps the pseudonyms of a project found in any text back to their
# originals, and looks up single values in both directions. Reads the project mapping only;
# reuses the scanner's multi-pattern matcher (the dependency points from reveal to scan, so the
# scanner stays independent of the anonymiser).
mcxanon_add_module(reveal
  SOURCES index.cpp recognise.cpp escape.cpp resolve.cpp render.cpp engine.cpp lookup.cpp report.cpp
  DEPS pseudo scan bytes
  EXTERNAL nlohmann_json::nlohmann_json)
