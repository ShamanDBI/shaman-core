#ifndef H_DEBUG_OPTS
#define H_DEBUG_OPTS

#include "memory.hpp"
#include "registers.hpp"
#include "modules.hpp"

struct DebugOpts {

	pid_t m_pid;

	RemoteMemory* m_memory = nullptr;
	Registers* m_register = nullptr;
	ProcessMap* m_procMap = nullptr;

	DebugOpts(pid_t tracee_pid) : m_pid(tracee_pid) {}
	~DebugOpts() { m_pid = 0; };

	DebugOpts& setPid(pid_t tracee_pid) {
		m_pid = tracee_pid;
		return *this;
	}

	pid_t getPid(pid_t tracee_pid) {
		return m_pid;
	}

	DebugOpts& setRemoteMemory(RemoteMemory* memory) {
		m_memory = memory;
		return *this;
	}
	
	DebugOpts& setRegisters(Registers* reg_obj) {
		m_register = reg_obj;
		return *this;
	}

	DebugOpts& setProcessMap(ProcessMap* procMap) {
		m_procMap = procMap;
		return *this;
	}
};

#endif
