#include "syscall_mngr.hpp"
#include <spdlog/spdlog.h>


#define SYSCALL_ID_INTEL 15 // INTEL_X64_REGS::ORIG_RAX
#define SYSCALL_ARG_0 14 // INTEL_X64_REGS::RDI
#define SYSCALL_ARG_1 13 // INTEL_X64_REGS::RSI
#define SYSCALL_ARG_2 12 // INTEL_X64_REGS::RDX
#define SYSCALL_ARG_3  7 // INTEL_X64_REGS::R10
#define SYSCALL_ARG_4  9 // INTEL_X64_REGS::R8
#define SYSCALL_ARG_5  8 // INTEL_X64_REGS::R9
#define SYSCALL_RET 10 // INTEL_X64_REGS::RAX


/**
 *  src : https://chromium.googlesource.com/chromiumos/docs/+/HEAD/constants/syscalls.md
 *	arch	syscall NR	return	arg0	arg1	arg2	arg3	arg4	arg5
 *	arm		r7			r0		r0		r1		r2		r3		r4		r5
 *	arm64	x8			x0		x0		x1		x2		x3		x4		x5
 *	x86	    eax			eax		ebx		ecx		edx		esi		edi		ebp
 *	x86_64	rax			rax		rdi		rsi		rdx		r10		r8		r9
*/
void SyscallManager::readParameters(DebugOpts* debug_opts) {
	debug_opts->m_register->getGPRegisters();
	m_cached_args->sc_id = debug_opts->m_register->getRegIdx(SYSCALL_ID_INTEL);
	
	// get the system call info
	if (m_cached_args->sc_id < MAX_SYSCALL_NUM)
		m_syscall_info = &syscalls[m_cached_args->sc_id];
	else 
		m_syscall_info = nullptr;
	
	m_cached_args->v_arg[0] = debug_opts->m_register->getRegIdx(SYSCALL_ARG_0);
	m_cached_args->v_arg[1] = debug_opts->m_register->getRegIdx(SYSCALL_ARG_1);
	m_cached_args->v_arg[2] = debug_opts->m_register->getRegIdx(SYSCALL_ARG_2);
	m_cached_args->v_arg[3] = debug_opts->m_register->getRegIdx(SYSCALL_ARG_3);
	m_cached_args->v_arg[4] = debug_opts->m_register->getRegIdx(SYSCALL_ARG_4);
	m_cached_args->v_arg[5] = debug_opts->m_register->getRegIdx(SYSCALL_ARG_5);
}

void SyscallManager::readRetValue(DebugOpts* debug_opts) {
	debug_opts->m_register->getGPRegisters();
	m_cached_args->v_rval = debug_opts->m_register->getRegIdx(SYSCALL_RET);
}

int SyscallManager::addFileOperationHandler(FileOperationTracer* file_opt_handler) {
	m_file_ops_pending.push_front(file_opt_handler);
	return 0;
}

int SyscallManager::removeFileOperationHandler(FileOperationTracer* file_opt_handler) {
	return 0;
}

int SyscallManager::addSyscallHandler(SyscallHandler* syscall_hdlr) {
	m_syscall_handler_map[syscall_hdlr->syscall_id] = syscall_hdlr;
	return 0;
}

int SyscallManager::removeSyscallHandler(SyscallHandler* syscall_hdlr) {
	// m_syscall_handler_map[syscall_hdlr->syscall_id] = syscall_hdlr;
	return 0;
}

int SyscallManager::onEnter(DebugOpts* debug_opts) {
	readParameters(debug_opts);
	
	// File operation detector
	if (file_ops_syscall_id.count(m_cached_args->sc_id)) {
		m_log->debug("FILE OPT DETECED");
		
		int fd = m_cached_args->v_arg[0];

		auto file_ops_iter = m_file_ops_handler.find(fd);  
     
	    if ( file_ops_iter == m_file_ops_handler.end() ) {  
	    	// Not found!
			m_log->trace("No FileOperation is registered for this fd");
	    } else {
	    	// Found
	    	FileOperationTracer* file_ops_obj = file_ops_iter->second;

	    	switch(m_cached_args->sc_id) {
	    	case NR_read:
	    		file_ops_obj->onRead();
	    		break;
	    	case NR_write:
	    		file_ops_obj->onWrite();
	    		break;
	    	case NR_close:
	    		file_ops_obj->onClose();
	    		break;
	    	case NR_ioctl:
	    		file_ops_obj->onIoctl();
	    		break;
	    	default:
	    		m_log->error("This FileOperation is not implemented!");
	    	}
	    }
	}

	// Find and invoke system call handler
	auto sys_iter = m_syscall_handler_map.find(m_cached_args->sc_id);  
     
    if ( sys_iter == m_syscall_handler_map.end() ) {  
    	// Not found!
		m_log->trace("No syscall handler is registered for this syscall number");
    } else {
    	// Found
    	SyscallHandler* syscall_hdlr = sys_iter->second;
    	syscall_hdlr->onEnter(debug_opts, m_cached_args);
    }  
	
	if(m_syscall_info)
		m_log->debug("NAME : -> {}", m_syscall_info->name);
	return 0;
}

int SyscallManager::onExit(DebugOpts* debug_opts) {
	if(m_syscall_info)
		m_log->debug("NAME : <- {} ()", m_syscall_info->name, m_cached_args->v_rval);
	readRetValue(debug_opts);
	FileOperationTracer* f_opts = nullptr;
	int fd = 0;
	// if(m_cached_args->sc_id == NR_openat) {
		// File operation detector
		for (auto file_opt_iter = m_file_ops_pending.begin();
			file_opt_iter != m_file_ops_pending.end();)
	    {
	    	f_opts = *file_opt_iter;
	        if (f_opts->onFilter(debug_opts, m_cached_args)) {
	        	f_opts->onOpen();
	        	// found the match, removing it from the list
	            file_opt_iter = m_file_ops_pending.erase(file_opt_iter);
	            fd = m_cached_args->v_rval;
	            m_file_ops_handler[fd] = f_opts;
	        } else {
	            ++file_opt_iter;
	        }
	    }
	// }

	// Find and invoke system call handler
	auto sys_iter = m_syscall_handler_map.find(m_cached_args->sc_id);  
     
    if ( sys_iter == m_syscall_handler_map.end() ) {  
    	// Not found!
		m_log->trace("No syscall handler is registered for this syscall number");
    } else {
    	// Found
    	SyscallHandler* syscall_hdlr = sys_iter->second;
    	syscall_hdlr->onExit(debug_opts, m_cached_args);
    }
	m_syscall_info = nullptr;
	return 0;
}