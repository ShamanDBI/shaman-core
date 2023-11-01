#ifndef H_DEBUG_OPTS
#define H_DEBUG_OPTS

#include "memory.hpp"
#include "registers.hpp"
#include "modules.hpp"


struct DebugOpts {

	pid_t m_pid;

	Registers& m_register;
	RemoteMemory& m_memory;
	ProcessMap& m_procMap;

	DebugOpts(pid_t _tracee_pid, Registers& _registers, 
		RemoteMemory& _remote_mem, ProcessMap& _proc_map) :
		m_pid(_tracee_pid), m_register(_registers),
		m_memory(_remote_mem),
		m_procMap(_proc_map) {}

	~DebugOpts() { m_pid = 0; };

	pid_t getPid() {
		return m_pid;
	}

	DebugOpts& setPid(pid_t tracee_pid) {
		m_pid = tracee_pid;
		m_register.setPid(tracee_pid);
		m_procMap.setPid(tracee_pid);
		return *this;
	};

	DebugOpts& setRemoteMemory(RemoteMemory& memory) {
		m_memory = memory;
		return *this;
	}
	
	DebugOpts& setRegisters(Registers& reg_obj) {
		m_register = reg_obj;
		return *this;
	}

	DebugOpts& setProcessMap(ProcessMap& procMap) {
		m_procMap = procMap;
		return *this;
	}
};


#endif
