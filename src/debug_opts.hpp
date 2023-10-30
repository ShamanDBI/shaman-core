#ifndef H_DEBUG_OPTS
#define H_DEBUG_OPTS

#include "memory.hpp"
#include "registers.hpp"
#include "modules.hpp"

template<class RegisterT>
struct DebugOpts {

	pid_t m_pid;

	RemoteMemory& m_memory;
	RegisterT& m_register;
	ProcessMap& m_procMap;

	DebugOpts(pid_t _tracee_pid) : 
		m_pid(_tracee_pid), m_register(RegisterT(_tracee_pid)),
		m_memory(RemoteMemory(_tracee_pid)),
		m_procMap(ProcessMap(_tracee_pid)) {}

	~DebugOpts() { m_pid = 0; };

	DebugOpts& setPid(pid_t tracee_pid) {
		m_pid = tracee_pid;
		return *this;
	}

	pid_t getPid() {
		return m_pid;
	}

	DebugOpts& setPid(pid_t tracee_pid) {
		m_pid = tracee_pid;
		m_register.setPid(tracee_pid);
		m_procMap.setPid(tracee_pid);
		return *this;
	};

	DebugOpts& setRemoteMemory(RemoteMemory* memory) {
		m_memory = memory;
		return *this;
	}
	
	DebugOpts& setRegisters(RegisterT* reg_obj) {
		m_register = reg_obj;
		return *this;
	}

	DebugOpts& setProcessMap(ProcessMap* procMap) {
		m_procMap = procMap;
		return *this;
	}
};


typedef DebugOpts<AMD64Register> AMD64DebugOpts;
typedef DebugOpts<X86Register> X86DebugOpts;
typedef DebugOpts<ARMRegister> ARM64DebugOpts;
typedef DebugOpts<ARM64Register> ARM64DebugOpts;

#endif
