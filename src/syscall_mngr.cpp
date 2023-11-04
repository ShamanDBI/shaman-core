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
void SyscallManager::readSyscallParams(DebugOpts& debug_opts) {
	AMD64Register& regObj = reinterpret_cast<AMD64Register&>(debug_opts.m_register);
	
	debug_opts.m_register.fetch();

	int16_t call_id = static_cast<int16_t>(regObj.getRegIdx(SYSCALL_ID_INTEL));
	spdlog::warn("raw call id {}", call_id);
	
	SysCallId sys_id = amd64_canonicalize_syscall(static_cast<AMD64_SYSCALL>(call_id));
	spdlog::warn("Syscall {}", sys_id.getString());
	m_cached_args.syscall_id = sys_id;
	
	m_cached_args.v_arg[0] = regObj.getRegIdx(SYSCALL_ARG_0);
	m_cached_args.v_arg[1] = regObj.getRegIdx(SYSCALL_ARG_1);
	m_cached_args.v_arg[2] = regObj.getRegIdx(SYSCALL_ARG_2);
	m_cached_args.v_arg[3] = regObj.getRegIdx(SYSCALL_ARG_3);
	m_cached_args.v_arg[4] = regObj.getRegIdx(SYSCALL_ARG_4);
	m_cached_args.v_arg[5] = regObj.getRegIdx(SYSCALL_ARG_5);
}

void SyscallManager::readRetValue(DebugOpts& debug_opts) {
	AMD64Register& regObj = reinterpret_cast<AMD64Register&>(debug_opts.m_register);
	regObj.fetch();
	m_cached_args.v_rval = regObj.getRegIdx(SYSCALL_RET);
}

int SyscallManager::addFileOperationHandler(FileOperationTracer* file_opt_handler) {
	m_file_ops_pending.push_front(file_opt_handler);
	return 0;
}

int SyscallManager::removeFileOperationHandler(FileOperationTracer* file_opt_handler) {
	return 0;
}

int SyscallManager::addSyscallHandler(SyscallHandler* syscall_hdlr) {
	m_syscall_handler_map.insert({syscall_hdlr->m_syscall_id.getIntValue(), syscall_hdlr});
	return 0;
}

int SyscallManager::removeSyscallHandler(SyscallHandler* syscall_hdlr) {
	// m_syscall_handler_map[syscall_hdlr->syscall_id] = syscall_hdlr;
	return 0;
}

int SyscallManager::handleFileOpt(SyscallState sys_state, DebugOpts& debug_opts) {
	int fd = static_cast<int>(m_cached_args.v_arg[0]);

	auto file_ops_iter = m_file_ops_handler.find(fd);  
	
	if ( file_ops_iter == m_file_ops_handler.end() ) {  
		// Not found!
		m_log->trace("No FileOperation is registered for this fd");
		return 0;
	}
	// Found
	FileOperationTracer* file_ops_obj = file_ops_iter->second;

	switch(m_cached_args.syscall_id.getValue()) {
	case SysCallId::READ :
		file_ops_obj->onRead(sys_state, debug_opts, m_cached_args);
		break;
	case SysCallId::WRITE :
		file_ops_obj->onWrite(sys_state, debug_opts, m_cached_args);
		break;
	case SysCallId::CLOSE :
		file_ops_obj->onClose(sys_state, debug_opts, m_cached_args);
		break;
	case SysCallId::IOCTL :
		file_ops_obj->onIoctl(sys_state, debug_opts, m_cached_args);
		break;
	default:
		m_log->error("This FileOperation is not implemented!");
	}
	return 0;
}

int SyscallManager::onEnter(DebugOpts& debug_opts) {
	readSyscallParams(debug_opts);
	spdlog::warn("ID {}", m_cached_args.getSyscallNo());
	// File operation handler
	if (file_ops_syscall_id.count(m_cached_args.getSyscallNo())) {
		m_log->trace("FILE OPT DETECED");
		handleFileOpt(SyscallState::ON_ENTER, debug_opts);
	}

	// Find and invoke system call handler
	auto map_key = m_cached_args.getSyscallNo();
	auto sc_handler_iter = m_syscall_handler_map.equal_range(map_key);
	bool sys_hdl_not_fnd = true;

	for (auto it=sc_handler_iter.first; it!=sc_handler_iter.second; ++it) {
		it->second->onEnter(m_cached_args);
		sys_hdl_not_fnd = false;
	}

    if (sys_hdl_not_fnd) {  
    	// Not found!
		m_log->trace("onEnter : No syscall handler is registered for this syscall number");
    }
	
	m_log->debug("NAME : -> {}", m_cached_args.syscall_id.getString());
	return 0;
}

int SyscallManager::onExit(DebugOpts& debug_opts) {
	m_log->debug("NAME : <- {} ()", m_cached_args.syscall_id.getString(), m_cached_args.v_rval);
	readRetValue(debug_opts);
	FileOperationTracer* f_opts = nullptr;
	int fd = 0;
	if(m_cached_args.syscall_id == SysCallId::OPENAT) {
		// File operation detector
		for (auto file_opt_iter = m_file_ops_pending.begin();
			file_opt_iter != m_file_ops_pending.end();)
	    {
	    	f_opts = *file_opt_iter;
	        if (f_opts->onFilter(debug_opts, m_cached_args)) {
	        	f_opts->onOpen(SyscallState::ON_EXIT, debug_opts, m_cached_args);
	        	// found the match, removing it from the list
	            file_opt_iter = m_file_ops_pending.erase(file_opt_iter);
	            fd = m_cached_args.v_rval;
	            m_file_ops_handler[fd] = f_opts;
	        } else {
	            ++file_opt_iter;
	        }
	    }
	}

	if (file_ops_syscall_id.count(m_cached_args.getSyscallNo())) {
		m_log->debug("FILE OPT DETECED");
		handleFileOpt(SyscallState::ON_EXIT, debug_opts);
	}
	
	// Find and invoke system call handler
	auto map_key = m_cached_args.getSyscallNo();
	auto sys_hd_iter = m_syscall_handler_map.equal_range(map_key);
	bool sys_hdl_not_fnd = true;

	for (auto it=sys_hd_iter.first; it!=sys_hd_iter.second; ++it) {
		it->second->onExit(m_cached_args);
		sys_hdl_not_fnd = false;
	}

    if (sys_hdl_not_fnd) {  
    	// Not found!
		m_log->trace("onExit : No syscall handler is registered for this syscall number");
    }
	return 0;
}