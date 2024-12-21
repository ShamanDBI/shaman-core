# Sample script to generate basic block info file for test_target program
rm -rf shaman_ghidra_projects/
mkdir shaman_ghidra_projects

TARGET_APP=builds/test_target/bin/test_target
TARGET_PARAMS=1

PIPE_ID=51900

# ghidra in action
$GHIDRA_HOME/support/analyzeHeadless shaman_ghidra_projects test_target -import $TARGET_APP -scriptPath $(pwd)/script/ -postscript ghidra_bb_expoter.py output_test

# this script will generate file output_test.bb

nohup builds/binary_coverage_app/binary_coverage -l app.log --cov-basic-block ./output_test.bb --pipe-id $PIPE_ID --exec    $TARGET_APP $TARGET_PARAMS &

sleep 1

builds/binary_coverage_app/binary_coverage_consumer $PIPE_ID