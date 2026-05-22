configure_file("CTestCustom.cmake" ${CMAKE_BINARY_DIR}/CTestCustom.cmake)

add_subdirectory(unit)
if(VALKEY_AUDIT_INTEGRATION_TESTS)
    add_subdirectory(integration)
endif()