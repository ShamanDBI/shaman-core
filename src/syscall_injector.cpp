#include "syscall_injector.hpp"

void SyscallInjector::injectSyscall(std::unique_ptr<SyscallInject> syscall_data)
{
	m_pending_syscall_inject.push_back(std::move(syscall_data));
}

/// @brief 'svc #0' Instruction encoding
static const uint8_t arm_linux_le_svc[] = {0x00, 0x00, 0x00, 0xef};

BreakpointPtr SyscallInjector::setUp(std::string& mod_name, std::uintptr_t brkpt_offset)
{
	m_setup_breakpoint = new SyscallInjectorBreakpoint(mod_name, brkpt_offset, *this);
	return m_setup_breakpoint;
}

void SyscallInjector::execute(TraceeProgram &traceeProg)
{
	/**
	 * The technique which we are using is syscall hijack, where we change the parameter
	 * of the syscall to inject our syscall and capture the return value. Once we are
	 * done inject the call we resume from the previous syscall to continue execution
	 * without harming the original follow of the program.
	 */

	// Rest of the code is to handle `onEnter` state
	if (m_pending_syscall_inject.size() == 0)
	{
		m_log->debug("We don't have syscall to inject");
		return;
	}
	m_log->debug("Injecting syscall into the Tracee");
	DebugOpts &debug_opts = traceeProg.m_debug_opts;
	ARM32Register *armRegObj = dynamic_cast<ARM32Register *>(&debug_opts.m_register);
	armRegObj->fetch();

	// Pop one syscall which we want to inject
	traceeProg.m_inject_call = std::move(m_pending_syscall_inject.back());
	m_pending_syscall_inject.pop_back();

	saveProgramState(traceeProg);
    
	const uint32_t arm_inst_size = 4;
	// address of the next instruction after the breakpoint address
	std::uintptr_t bkpt_pc = armRegObj->getProgramCounter() + arm_inst_size;
	
	m_log->debug("Instruction injection addr {:x}", bkpt_pc);
	
	// Replace the program instruction with syscall instruction
	AddrPtr inst_backup = debug_opts.m_memory.readPointerObj(bkpt_pc, arm_inst_size);
	uint8_t* tmp_backup_byte = inst_backup->get_buffer_copy();
	m_backup_inst = inst_backup;
	
	// Write 'svc 0' instruction to the program memory
	inst_backup->copy_buffer(arm_linux_le_svc, sizeof(arm_linux_le_svc)); 
	debug_opts.m_memory.writeRemoteAddrObj(*inst_backup, sizeof(arm_linux_le_svc));
	
	inst_backup->copy_buffer(const_cast<uint8_t *>(tmp_backup_byte), inst_backup->size()); 
	free(tmp_backup_byte);

	// armRegObj->print();
	// Write the sycall parameter to the Register
	setSyscallParams(traceeProg);
}

void SyscallInjector::setSyscallParams(TraceeProgram &traceeProg) {
	DebugOpts &debug_opts = traceeProg.m_debug_opts;
	ARM32Register *armRegObj = dynamic_cast<ARM32Register *>(&debug_opts.m_register);
	switch (traceeProg.m_target_desc.m_cpu_arch)
	{
	case CPU_ARCH::ARM32:
		// Setup syscall ID
		armRegObj->setRegIdx(ARM32Register::R7, traceeProg.m_inject_call->m_syscall_id);
		// setup sycall parameter
		armRegObj->setRegIdx(ARM32Register::R0, traceeProg.m_inject_call->m_sys_args[0]);
		armRegObj->setRegIdx(ARM32Register::R1, traceeProg.m_inject_call->m_sys_args[1]);
		armRegObj->setRegIdx(ARM32Register::R2, traceeProg.m_inject_call->m_sys_args[2]);
		armRegObj->setRegIdx(ARM32Register::R3, traceeProg.m_inject_call->m_sys_args[3]);
		armRegObj->setRegIdx(ARM32Register::R4, traceeProg.m_inject_call->m_sys_args[4]);
		armRegObj->setRegIdx(ARM32Register::R5, traceeProg.m_inject_call->m_sys_args[5]);
		armRegObj->update();
		break;
	default:
		m_log->error("Syscall injection is not supported this CPU Architecture");
	}
}

void SyscallInjector::saveProgramState(TraceeProgram &traceeProg) {
	DebugOpts &debug_opts = traceeProg.m_debug_opts;
	m_log->trace("Saving Program State");
	debug_opts.m_register.fetch();
	// Create a copy of register state which will be restored later
	m_gp_register_copy = debug_opts.m_register.getRegisterCopy();
}

void SyscallInjector::restoreProgramState(TraceeProgram &traceeProg) {
	DebugOpts &debug_opts = traceeProg.m_debug_opts;
	m_log->trace("Restoring Program State");
	// Restore original instruction
	debug_opts.m_memory.writeRemoteAddrObj(*m_backup_inst, sizeof(arm_linux_le_svc));
	// Restore origingal state Where we hijacked the program flow
	// this will also restore original PC value
	debug_opts.m_register.restoreRegisterCopy(m_gp_register_copy);
	debug_opts.m_register.update();
}


void SyscallInjector::cleanUp(TraceeProgram &traceeProg) {
	DebugOpts &debug_opts = traceeProg.m_debug_opts;
	ARM32Register *armRegObj = dynamic_cast<ARM32Register *>(&debug_opts.m_register);
	armRegObj->fetch();
	m_log->debug("Syscall Injection Done!");

	// armRegObj->print();
	traceeProg.m_inject_call->m_ret_value = armRegObj->getRegIdx(ARM32Register::R0);
	m_log->debug("Inject Return value : {:x}", traceeProg.m_inject_call->m_ret_value);
	traceeProg.m_inject_call->onComplete();

	if (m_pending_syscall_inject.size() == 0)
	{
		m_log->debug("We don't have anything else to inject");
		restoreProgramState(traceeProg);

		// Since we don't have anything else to inject, we clean up everything
		if(m_gp_register_copy) {
			free((void *)m_gp_register_copy);
			delete m_backup_inst;
		}

		// clean the last attached syscall
		traceeProg.m_inject_call.reset();
		m_log->debug("All the Syscall injection is done");
		return;
	}

	m_log->debug("Injecting next syscall");
	
	// Pop one syscall which we want to inject
	std::unique_ptr<SyscallInject> inject_syscall = std::move(m_pending_syscall_inject.back());
	m_pending_syscall_inject.pop_back();
	
	// These two variable represent program state and they are passed to the next 
	// inject call, May be don't need to put it here!
	const uint32_t arm_inst_size = 4;
	// address of the previous instruction after the breakpoint address
	armRegObj->setProgramCounter(armRegObj->getProgramCounter() - arm_inst_size);
	// traceeProg.m_inject_call.reset();
	traceeProg.m_inject_call = std::move(inject_syscall);
	setSyscallParams(traceeProg);
}