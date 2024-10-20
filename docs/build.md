# How to build?

## Compiling

`./scripts/build.sh`

## Running

### Generate Basic block address

```bash
/home/hussain/tools/ghidra/support/analyzeHeadless tmp_proj HeadlessAnalysis -import ./build/bin/test_prog -scriptPath /home/hussain/ghidra_scripts/ -postscript export_basic_block.py
```