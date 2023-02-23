#include "syscall_mngr.hpp"
#include "syscall_x64.h"
#include <spdlog/spdlog.h>

// #define SYSCALL_ID_INTEL INTEL_X64_REGS::ORIG_RAX
// #define SYSCALL_ARG_0 INTEL_X64_REGS::RDI
// #define SYSCALL_ARG_1 INTEL_X64_REGS::RSI
// #define SYSCALL_ARG_2 INTEL_X64_REGS::RDX
// #define SYSCALL_ARG_3 INTEL_X64_REGS::R10
// #define SYSCALL_ARG_4 INTEL_X64_REGS::R8
// #define SYSCALL_ARG_5 INTEL_X64_REGS::R9

#define SYSCALL_ID_INTEL 15

/**
 *  src : https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md 
 *	arch	syscall NR	return	arg0	arg1	arg2	arg3	arg4	arg5
 *	arm		r7			r0		r0		r1		r2		r3		r4		r5
 *	arm64	x8			x0		x0		x1		x2		x3		x4		x5
 *	x86	    eax			eax		ebx		ecx		edx		esi		edi		ebp
 *	x86_64	rax			rax		rdi		rsi		rdx		r10		r8		r9
*/
void SyscallHandler::readParameters() {
	m_register->getGPRegisters();
	uint16_t syscall_id = m_register->getRegIdx(SYSCALL_ID_INTEL);
	m_cached_args = &syscalls[syscall_id];
}

int SyscallHandler::onEnter() {
	readParameters();
	spdlog::debug("NAME : -> {}", m_cached_args->name);
	return 0;
}

int SyscallHandler::onExit() {
	spdlog::debug("NAME : <- {}", m_cached_args->name);
	m_cached_args = nullptr;
	return 0;
}