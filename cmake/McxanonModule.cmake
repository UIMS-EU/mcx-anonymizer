# SPDX-License-Identifier: GPL-3.0-or-later
#
# mcxanon_add_module(<name> [SOURCES ...] [DEPS ...] [EXTERNAL ...])
#
# Creates the internal library target mcxanon_<name>. A module that has no
# sources yet is an INTERFACE library, so the dependency graph exists from the
# start and is checked from the start. DEPS are other modules (short names),
# EXTERNAL are imported targets of third-party packages.

set(MCXANON_WARNINGS -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Werror)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  # GCC 14 reports a false positive for std::vector<unsigned char> comparisons
  # (std::map keys) at -O3: "specified bound ... exceeds maximum object size".
  list(APPEND MCXANON_WARNINGS -Wno-stringop-overread)
endif()

function(mcxanon_set_warnings target)
  target_compile_options(${target} PRIVATE ${MCXANON_WARNINGS})
endfunction()

function(mcxanon_add_module name)
  cmake_parse_arguments(ARG "" "" "SOURCES;DEPS;EXTERNAL" ${ARGN})
  set(target mcxanon_${name})
  set(deps "")
  foreach(d IN LISTS ARG_DEPS)
    list(APPEND deps mcxanon_${d})
  endforeach()

  if(ARG_SOURCES)
    add_library(${target} STATIC ${ARG_SOURCES})
    target_include_directories(${target}
      PUBLIC "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src"
             "${PROJECT_BINARY_DIR}/generated")
    target_link_libraries(${target} PUBLIC ${deps} ${ARG_EXTERNAL})
    mcxanon_set_warnings(${target})
  else()
    add_library(${target} INTERFACE)
    target_include_directories(${target}
      INTERFACE "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src"
                "${PROJECT_BINARY_DIR}/generated")
    target_link_libraries(${target} INTERFACE ${deps} ${ARG_EXTERNAL})
  endif()
  set_property(TARGET ${target} PROPERTY MCXANON_MODULE_DEPS "${deps}")
  set_property(TARGET ${target} PROPERTY MCXANON_MODULE_EXTERNAL "${ARG_EXTERNAL}")
endfunction()

# Fails the configure step if <target> links anything outside <allowed...>.
function(mcxanon_assert_links_only target)
  set(allowed ${ARGN})
  get_target_property(type ${target} TYPE)
  if(type STREQUAL "INTERFACE_LIBRARY")
    get_target_property(links ${target} INTERFACE_LINK_LIBRARIES)
  else()
    get_target_property(links ${target} LINK_LIBRARIES)
  endif()
  if(NOT links)
    return()
  endif()
  foreach(l IN LISTS links)
    if(NOT l IN_LIST allowed)
      message(FATAL_ERROR
        "${target} links '${l}', but it may link only: ${allowed}. "
        "See the module dependency direction in src/CMakeLists.txt; the scanner must stay "
        "independent of the anonymiser.")
    endif()
  endforeach()
endfunction()
