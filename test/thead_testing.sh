cmake --build build --target shaman --target test_prog
rm -rf tmp_proj
mkdir tmp_proj
/home/hussain/tools/ghidra/support/analyzeHeadless tmp_proj HeadlessAnalysis -import ./build/bin/test_prog -scriptPath /home/hussain/ghidra_scripts/ -postscript export_basic_block.py
rm -rf app.log prog.cov
./build/bin/shaman -l app.log --debug 0 -s -f -c ./build/test_prog_1.bb --cov-out prog.cov -e build/bin/test_prog | wc -l
grep "We are writing coverag" app.log  | wc -l
python3 script/coverage_parser.py prog.cov | head 
