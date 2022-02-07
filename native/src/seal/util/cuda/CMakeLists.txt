# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(SEAL_SOURCE_FILES ${SEAL_SOURCE_FILES}
        ${CMAKE_CURRENT_LIST_DIR}/main.cu
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/main.cuh
    DESTINATION
        ${SEAL_INCLUDES_INSTALL_DIR}/seal/util
)

set(SEAL_SOURCE_FILES ${SEAL_SOURCE_FILES} PARENT_SCOPE)
