# Unit tests for the portable core. Plain C, no framework — a tiny assert macro
# in pmx_test.h. Each file is its own CTest case.

set(PMX_TESTS
    test_socks
    test_profile_json
    test_protect
    test_rules
    test_chain_failover
    test_procinfo
    test_socks_e2e
    test_relay
    test_decide_snapshot
    test_netpath
    test_vpn
    test_proc
    test_nat
    test_relay_chain
)

foreach(t ${PMX_TESTS})
    add_executable(${t} ${t}.c)
    target_link_libraries(${t} PRIVATE pmx::core)
    target_include_directories(${t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    pmx_set_warnings(${t})
    add_test(NAME ${t} COMMAND ${t})
endforeach()
