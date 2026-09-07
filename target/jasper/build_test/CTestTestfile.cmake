# CMake generated Testfile for 
# Source directory: /data/ylwang/non-textfuzz/target/jasper
# Build directory: /data/ylwang/non-textfuzz/target/jasper/build_test
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(run_test_1 "/usr/bin/bash" "/data/ylwang/non-textfuzz/target/jasper/build_test/test/bin/wrapper" "/data/ylwang/non-textfuzz/target/jasper/test/bin/run_test_1")
set_tests_properties(run_test_1 PROPERTIES  _BACKTRACE_TRIPLES "/data/ylwang/non-textfuzz/target/jasper/CMakeLists.txt;393;add_test;/data/ylwang/non-textfuzz/target/jasper/CMakeLists.txt;0;")
add_test(run_test_2 "/usr/bin/bash" "/data/ylwang/non-textfuzz/target/jasper/build_test/test/bin/wrapper" "/data/ylwang/non-textfuzz/target/jasper/test/bin/run_test_2")
set_tests_properties(run_test_2 PROPERTIES  _BACKTRACE_TRIPLES "/data/ylwang/non-textfuzz/target/jasper/CMakeLists.txt;396;add_test;/data/ylwang/non-textfuzz/target/jasper/CMakeLists.txt;0;")
add_test(run_test_3 "/usr/bin/bash" "/data/ylwang/non-textfuzz/target/jasper/build_test/test/bin/wrapper" "/data/ylwang/non-textfuzz/target/jasper/test/bin/run_test_3")
set_tests_properties(run_test_3 PROPERTIES  _BACKTRACE_TRIPLES "/data/ylwang/non-textfuzz/target/jasper/CMakeLists.txt;399;add_test;/data/ylwang/non-textfuzz/target/jasper/CMakeLists.txt;0;")
add_test(run_test_4 "/usr/bin/bash" "/data/ylwang/non-textfuzz/target/jasper/build_test/test/bin/wrapper" "/data/ylwang/non-textfuzz/target/jasper/test/bin/run_test_4")
set_tests_properties(run_test_4 PROPERTIES  _BACKTRACE_TRIPLES "/data/ylwang/non-textfuzz/target/jasper/CMakeLists.txt;402;add_test;/data/ylwang/non-textfuzz/target/jasper/CMakeLists.txt;0;")
subdirs("src/libjasper")
subdirs("src/appl")
subdirs("doc")
