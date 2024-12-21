# Sample script to generate basic block info file for test_target program
rm -rf shaman_ghidra_projects/
mkdir shaman_ghidra_projects

# ghidra in action
$GHIDRA_HOME/support/analyzeHeadless shaman_ghidra_projects test_target -import builds/test_target/bin/test_target -scriptPath $(pwd)/script/ -postscript ghidra_bb_expoter.py output_test

# this script will generate file output_test.bb