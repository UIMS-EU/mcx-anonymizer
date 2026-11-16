# SPDX-License-Identifier: GPL-3.0-or-later
# The report schema is embedded for the report self-check, which skips the schema's own
# vocabulary (property names and enumeration values; src/report/self_check.hpp).
set(_schema "${PROJECT_SOURCE_DIR}/schemas/report.schema.json")
set_property(DIRECTORY "${PROJECT_SOURCE_DIR}" APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_schema}")
file(READ "${_schema}" _schema_text)
if(_schema_text MATCHES "\\)mcxschema\"")
  message(FATAL_ERROR "report.schema.json contains the raw-string delimiter")
endif()
file(WRITE "${PROJECT_BINARY_DIR}/generated/report_schema_embedded.inc"
     "R\"mcxschema(${_schema_text})mcxschema\"\n")
mcxanon_add_module(report
  SOURCES json.cpp
  DEPS bytes
  EXTERNAL nlohmann_json::nlohmann_json)
