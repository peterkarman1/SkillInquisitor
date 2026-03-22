---
name: cmake-modern
description: Write correct, target-based CMake using PUBLIC/PRIVATE/INTERFACE visibility, FetchContent for dependencies, generator expressions, install/export for packaging, and CMakePresets for reproducible builds.
---

# Modern CMake

## Core Principle: Targets and Properties

Think of targets as objects. `add_library` / `add_executable` are constructors. The `target_*` commands are member functions that set properties.

```cmake
cmake_minimum_required(VERSION 3.15...4.1)
project(MyLib VERSION 1.0 LANGUAGES CXX)

add_library(mylib src/mylib.cpp)
target_include_directories(mylib PUBLIC include)
target_compile_features(mylib PUBLIC cxx_std_17)
target_link_libraries(mylib PRIVATE fmt::fmt)
```

### PUBLIC vs PRIVATE vs INTERFACE

This is the most misunderstood part of CMake. The keywords control **transitive propagation** to targets that link against yours.

- **PRIVATE**: Used only to build this target. Does not propagate to dependents. Example: an internal implementation dependency.
- **PUBLIC**: Used to build this target AND propagated to anything that links to it. Example: a header exposes types from a dependency.
- **INTERFACE**: Not used to build this target, but propagated to dependents. Example: a header-only library (no compilation step, only consumers need the includes).

```cmake
# mylib uses nlohmann_json in its headers (public API)
target_link_libraries(mylib PUBLIC nlohmann_json::nlohmann_json)

# mylib uses spdlog only internally (not in headers)
target_link_libraries(mylib PRIVATE spdlog::spdlog)

# header-only library -- nothing to compile, consumers get the includes
add_library(myheaderlib INTERFACE)
target_include_directories(myheaderlib INTERFACE include)
target_compile_features(myheaderlib INTERFACE cxx_std_20)
```

**Rule of thumb**: If a dependency appears in your public headers, use PUBLIC. If it is only in `.cpp` files, use PRIVATE.

## FetchContent for Dependencies

FetchContent downloads and builds dependencies at configure time. It replaced ExternalProject for most use cases.

```cmake
include(FetchContent)

FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG        10.2.1
)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.14.0
)

FetchContent_MakeAvailable(fmt googletest)
```

### FetchContent Pitfalls

- **Declare before MakeAvailable**: All `FetchContent_Declare` calls for transitive dependencies must happen before `FetchContent_MakeAvailable` for any dependency that depends on them. The first declaration of a name wins -- later declarations are silently ignored.
- **Target name clashes**: FetchContent pulls the dependency's entire CMake tree into yours. If two dependencies define the same target name, the build fails. There is no namespace isolation.
- **CTest pollution**: Fetched dependencies that call `enable_testing()` and `add_test()` will add their tests to your CTest run. Guard with `option(BUILD_TESTING OFF)` before fetching, or set the dependency's testing option (e.g., `set(FMT_TEST OFF CACHE BOOL "" FORCE)`).
- **Prefer find_package first**: Use `FIND_PACKAGE_ARGS` (CMake 3.24+) to try `find_package` before downloading:

```cmake
FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG        10.2.1
  FIND_PACKAGE_ARGS  # tries find_package(fmt) first
)
```

## find_package: CONFIG vs MODULE

```cmake
find_package(Boost 1.80 REQUIRED COMPONENTS filesystem)
```

- **MODULE mode** (default first): CMake searches for `FindBoost.cmake` -- a find module shipped with CMake or the project. These modules set variables and define imported targets.
- **CONFIG mode**: CMake searches for `BoostConfig.cmake` / `boost-config.cmake` -- a config file shipped by the package itself. This is the preferred modern approach because the package author controls target names and properties.
- **Both**: By default CMake tries Module mode then Config mode. Use `find_package(Foo CONFIG REQUIRED)` to skip Module mode entirely.

Always link to the exported targets (`Boost::filesystem`), never use the old-style variables (`${Boost_LIBRARIES}`).

## Generator Expressions

Generator expressions are evaluated at build-system generation time, not at configure time. They are essential for packaging and multi-config generators.

### BUILD_INTERFACE vs INSTALL_INTERFACE

These filter paths depending on whether the target is used from the build tree or after installation:

```cmake
target_include_directories(mylib
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
```

Without this, exported targets would embed absolute build-tree paths, which break on other machines.

### Other Useful Generator Expressions

```cmake
# Conditional compile definition per configuration
target_compile_definitions(mylib PRIVATE
  $<$<CONFIG:Debug>:MY_DEBUG=1>
)

# Compiler-specific warning flags
target_compile_options(mylib PRIVATE
  $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra>
  $<$<CXX_COMPILER_ID:MSVC>:/W4>
)

# Reference to the built file of another target
add_custom_command(
  OUTPUT generated.h
  COMMAND $<TARGET_FILE:my_codegen_tool> --output generated.h
)
```

## Install and Export

The install/export system lets downstream projects consume your library via `find_package`.

### Step 1: Install Targets

```cmake
include(GNUInstallDirs)

install(TARGETS mylib
  EXPORT MyLibTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
```

### Step 2: Install the Export File

```cmake
install(EXPORT MyLibTargets
  FILE MyLibTargets.cmake
  NAMESPACE MyLib::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/MyLib
)
```

### Step 3: Create a Package Config File

```cmake
include(CMakePackageConfigHelpers)

configure_package_config_file(
  cmake/MyLibConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/MyLibConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/MyLib
)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/MyLibConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/MyLibConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/MyLibConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/MyLib
)
```

The `MyLibConfig.cmake.in` template:

```cmake
@PACKAGE_INIT@
include("${CMAKE_CURRENT_LIST_DIR}/MyLibTargets.cmake")
check_required_components(MyLib)
```

### Step 4: Create an Alias for Consistency

Create an alias so that in-tree usage looks the same as installed usage:

```cmake
add_library(MyLib::mylib ALIAS mylib)
```

Now consumers always write `target_link_libraries(app PRIVATE MyLib::mylib)` regardless of whether the library is found via `find_package` or built in the same tree.

## CMake Presets

`CMakePresets.json` (checked into version control) standardizes configure/build/test options across developers and CI.

```json
{
  "version": 6,
  "configurePresets": [
    {
      "name": "dev-debug",
      "binaryDir": "${sourceDir}/build/debug",
      "cacheVariables": {
        "CMAKE_BUILD_TYPE": "Debug",
        "BUILD_TESTING": "ON"
      }
    },
    {
      "name": "release",
      "binaryDir": "${sourceDir}/build/release",
      "cacheVariables": {
        "CMAKE_BUILD_TYPE": "Release",
        "BUILD_TESTING": "OFF"
      }
    }
  ],
  "buildPresets": [
    {
      "name": "dev-debug",
      "configurePreset": "dev-debug"
    }
  ],
  "testPresets": [
    {
      "name": "dev-debug",
      "configurePreset": "dev-debug",
      "output": { "outputOnFailure": true }
    }
  ]
}
```

Usage: `cmake --preset dev-debug && cmake --build --preset dev-debug && ctest --preset dev-debug`.

`CMakeUserPresets.json` is for personal overrides and should be in `.gitignore`.

## Testing with CTest

```cmake
# In top-level CMakeLists.txt
enable_testing()

# In tests/CMakeLists.txt
add_executable(mylib_tests test_main.cpp test_foo.cpp)
target_link_libraries(mylib_tests PRIVATE mylib GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(mylib_tests)
```

`gtest_discover_tests` is preferred over `add_test` for GoogleTest because it queries the test binary at build time and registers each test case individually, enabling granular `ctest -R` filtering.

For non-GoogleTest tests, use `add_test` directly:

```cmake
add_test(NAME mytest COMMAND mylib_tests --some-flag)
set_tests_properties(mytest PROPERTIES TIMEOUT 30)
```

Guard test-only targets so they are not built when your project is consumed as a subdirectory:

```cmake
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
  add_subdirectory(tests)
endif()
```

## Common Anti-Patterns

| Anti-pattern | Why it is wrong | Fix |
|---|---|---|
| `include_directories(...)` | Directory-scope, creates hidden dependencies | `target_include_directories(tgt ...)` |
| `link_directories(...)` | Directory-scope, fragile | `target_link_libraries(tgt ...)` with full target or path |
| `add_definitions(-DFOO)` | Directory-scope | `target_compile_definitions(tgt PRIVATE FOO)` |
| `set(CMAKE_CXX_FLAGS "-std=c++17")` | Compiler-specific, does not propagate | `target_compile_features(tgt PUBLIC cxx_std_17)` |
| `file(GLOB SOURCES "src/*.cpp")` | CMake does not re-run when files are added/removed | List source files explicitly |
| `set(CMAKE_CXX_STANDARD 17)` at directory level | Applies to all targets in scope | `target_compile_features` per target |
| Adding `-Wall` to PUBLIC/INTERFACE | Forces warning flags on consumers | Use PRIVATE for warning flags |
| Missing visibility keywords | Defaults to PUBLIC for `target_link_libraries`, causing unintended propagation | Always specify PUBLIC/PRIVATE/INTERFACE |

## Policy Management

`cmake_minimum_required(VERSION X.Y)` sets all policies introduced up to version X.Y to NEW behavior. Use the range syntax to express "works back to 3.15, tested up to 4.1":

```cmake
cmake_minimum_required(VERSION 3.15...4.1)
```

This lets users with newer CMake get newer policy defaults while still supporting older versions. Avoid setting individual policies with `cmake_policy(SET CMP0XXX NEW)` unless you have a specific reason -- the version range is almost always sufficient.

