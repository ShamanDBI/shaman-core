#ifndef H_DEBUG_OPTS
#define H_DEBUG_OPTS

#include "memory.hpp"
#include "registers.hpp"
#include "modules.hpp"


class DebugOpts {
public:
	pid_t m_pid;

	Registers& m_register;
	RemoteMemory& m_memory;
	ProcessMap& m_procMap;

	DebugOpts(pid_t _tracee_pid, Registers& _registers, 
		RemoteMemory& _remote_mem, ProcessMap& _proc_map);

	~DebugOpts();

	pid_t getPid();

	DebugOpts& setPid(pid_t tracee_pid);

	DebugOpts& setRemoteMemory(RemoteMemory& memory);
	
	DebugOpts& setRegisters(Registers& reg_obj);

	DebugOpts& setProcessMap(ProcessMap& procMap);
};


#endif
