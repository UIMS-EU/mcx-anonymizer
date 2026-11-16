# SPDX-License-Identifier: GPL-3.0-or-later
from conan import ConanFile
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout


class McxAnonymizerConan(ConanFile):
    name = "mcx-anonymizer"
    license = "GPL-3.0-or-later"
    description = "Anonymizer for Mission Critical (MCPTT/MCData/MCVideo) packet captures"
    settings = "os", "compiler", "build_type", "arch"

    # Every dependency must be permissively licensed; see tools/check-licenses.py.
    requires = (
        "openssl/3.5.9",        # Apache-2.0: HMAC, CSPRNG, Argon2id, ChaCha20-Poly1305
        "rapidyaml/0.15.2",     # MIT: rule set
        "cli11/2.7.2",          # BSD-3-Clause: command line
        "nlohmann_json/3.12.0", # MIT: report and mapping
    )
    default_options = {
        "openssl/*:no_zlib": True,
        "openssl/*:shared": False,
        # No networking code in the binary at all (offline by design).
        "openssl/*:no_sock": True,
        "openssl/*:no_dgram": True,
        "openssl/*:no_engine": True,  # no engines (the AF_ALG engine would bring socket calls)
    }

    def build_requirements(self):
        self.test_requires("catch2/3.16.1")  # BSL-1.0

    def layout(self):
        cmake_layout(self)

    def generate(self):
        CMakeToolchain(self).generate()
        CMakeDeps(self).generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
