#include "debug_opts.hpp"
#include "modules.hpp"


DebugOpts::DebugOpts(pid_t _tracee_pid, Registers& _registers, 
    RemoteMemory& _remote_mem, ProcessMap& _proc_map) :
    m_pid(_tracee_pid), m_register(_registers),
    m_memory(_remote_mem),
    m_procMap(_proc_map) {}

DebugOpts::~DebugOpts() {
    m_pid = 0;
};

pid_t DebugOpts::getPid() {
    return m_pid;
}

DebugOpts& DebugOpts::setPid(pid_t tracee_pid) {
    m_pid = tracee_pid;
    m_register.setPid(tracee_pid);
    m_procMap.setPid(tracee_pid);
    return *this;
};

DebugOpts& DebugOpts::setRemoteMemory(RemoteMemory& memory) {
    m_memory = memory;
    return *this;
};

DebugOpts& DebugOpts::setRegisters(Registers& reg_obj) {
    m_register = reg_obj;
    return *this;
};

DebugOpts& DebugOpts::setProcessMap(ProcessMap& procMap) {
    m_procMap = procMap;
    return *this;
};
