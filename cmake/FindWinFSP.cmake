# FindWinFSP.cmake
# Locate WinFSP installation on Windows
#
# This module defines:
#   WINFSP_FOUND - System has WinFSP
#   WINFSP_INCLUDE_DIR - The WinFSP include directory
#   WINFSP_LIBRARY - The WinFSP library
#   WINFSP_DLL - The WinFSP DLL (for runtime)

if(WIN32)
    # Search paths for WinFSP installation
    set(WINFSP_SEARCH_PATHS
        "$ENV{ProgramFiles\(x86\)}/WinFsp"
        "$ENV{ProgramFiles}/WinFsp"
        "$ENV{WINFSP_PATH}"
        "C:/Program Files (x86)/WinFsp"
        "C:/Program Files/WinFsp"
    )

    # Find include directory
    find_path(WINFSP_INCLUDE_DIR
        NAMES winfsp/winfsp.h
        PATHS ${WINFSP_SEARCH_PATHS}
        PATH_SUFFIXES inc
    )

    # Determine architecture suffix
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(WINFSP_ARCH "x64")
    else()
        set(WINFSP_ARCH "x86")
    endif()

    # Find library
    find_library(WINFSP_LIBRARY
        NAMES "winfsp-${WINFSP_ARCH}"
        PATHS ${WINFSP_SEARCH_PATHS}
        PATH_SUFFIXES lib
    )

    # Find DLL for runtime
    find_file(WINFSP_DLL
        NAMES "winfsp-${WINFSP_ARCH}.dll"
        PATHS ${WINFSP_SEARCH_PATHS}
        PATH_SUFFIXES bin
    )

    # Handle standard find_package arguments
    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(WinFSP
        REQUIRED_VARS
            WINFSP_INCLUDE_DIR
            WINFSP_LIBRARY
        FAIL_MESSAGE
            "Could not find WinFSP. Please install WinFSP from https://winfsp.dev/ or set WINFSP_PATH environment variable."
    )

    if(WINFSP_FOUND)
        # Create imported target
        if(NOT TARGET WinFSP::WinFSP)
            add_library(WinFSP::WinFSP UNKNOWN IMPORTED)
            set_target_properties(WinFSP::WinFSP PROPERTIES
                IMPORTED_LOCATION "${WINFSP_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${WINFSP_INCLUDE_DIR}"
            )
        endif()

        message(STATUS "Found WinFSP: ${WINFSP_INCLUDE_DIR}")
        message(STATUS "  Library: ${WINFSP_LIBRARY}")
        if(WINFSP_DLL)
            message(STATUS "  DLL: ${WINFSP_DLL}")
        endif()
    endif()

    mark_as_advanced(WINFSP_INCLUDE_DIR WINFSP_LIBRARY WINFSP_DLL)
else()
    set(WINFSP_FOUND FALSE)
endif()
