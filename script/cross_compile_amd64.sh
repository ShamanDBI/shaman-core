cmake -S . -B build -DCAPSTONE_ARM64_SUPPORT=0 -DCAPSTONE_M68K_SUPPORT=0 -DCAPSTONE_SPARC_SUPPORT=0 -DCAPSTONE_SYSZ_SUPPORT=0 -DCAPSTONE_XCORE_SUPPORT=0 -DCAPSTONE_TMS320C64X_SUPPORT=0 -DCAPSTONE_M680X_SUPPORT=0 -DCAPSTONE_EVM_SUPPORT=0 -DCAPSTONE_MOS65XX_SUPPORT=0 -DCAPSTONE_WASM_SUPPORT=0 -DCAPSTONE_BPF_SUPPORT=0 -DCAPSTONE_RISCV_SUPPORT=0 -DCAPSTONE_SH_SUPPORT=0 -DCAPSTONE_TRICORE_SUPPORT=0 -DCAPSTONE_ARM_SUPPORT=1 -DCAPSTONE_X86_SUPPORT=0 -DCAPSTONE_MIPS_SUPPORT=0 -DCAPSTONE_PPC_SUPPORT=0

cmake --build build --target shaman --target test_prog