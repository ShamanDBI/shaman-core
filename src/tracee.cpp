#include "tracee.hpp"
#include "syscall_x64.hpp"

// returns true if the tracee is in valid state
bool TraceeProgram::isValidState() {
	return m_state != TraceeState::UNKNOWN;
}

DebugType TraceeProgram::getChildDebugType() {
	if (debugType | DebugType::FOLLOW_FORK) {
		return debugType;
	} else {
		return DebugType::DEFAULT;
	}
}

bool TraceeProgram::isInitialized() {
	return m_state == INITIAL_STOP;
}

void TraceeProgram::toStateRunning() {
	m_state = TraceeState::RUNNING;
}

void TraceeProgram::toStateSysCall() {
	m_state = TraceeState::IN_SYSCALL;
}

void TraceeProgram::toStateExited() {
	m_state = TraceeState::EXITED;
}

bool TraceeProgram::hasExited() {
	return m_state == TraceeState::EXITED;
}

int TraceeProgram::contExecution(uint32_t sig) {
	int pt_ret = -1;
	int mode = debugType | DebugType::DEFAULT;
	
	if (debugType & DebugType::DEFAULT) {
		m_log->trace("contExec Tracee CONT");
		pt_ret = ptrace(PTRACE_CONT, getPid(), 0L, sig);
	} else if (debugType & DebugType::SYSCALL) {
		m_log->trace("contExec Tracee Syscall");
		pt_ret = ptrace(PTRACE_SYSCALL, getPid(), 0L, sig);
	} else if (debugType & DebugType::SINGLE_STEP) {
		m_log->trace("contExec single step");
		pt_ret = ptrace(PTRACE_SINGLESTEP, getPid(), 0L, sig);
	}

	if(pt_ret < 0) {
		m_log->error("ptrace continue call failed! Err code : {} ", pt_ret);
	}
	return pt_ret;
}

int TraceeProgram::singleStep() {
	int pt_ret = ptrace(PTRACE_SINGLESTEP, getPid(), 0L, 0);
	if(pt_ret < 0) {
		m_log->error("failed to single step! Err code : {} ", pt_ret);
	}
	return pt_ret;
}

std::string TraceeProgram::getStateString() {
	switch (m_state) {
		case TraceeState::INITIAL_STOP:
			return std::string("INIT Stop");
			break;
		case TraceeState::RUNNING:
			return std::string("RUNNING");
			break;
		case TraceeState::IN_SYSCALL:
			return std::string("SYSCALL");
			break;
		case TraceeState::EXITED:
			return std::string("EXITED");
			break;
		case TraceeState::UNKNOWN:
			return std::string("UNKNOWN");
			break;
		default:
			return std::string("UNKNOWN");
			break;
	};
}

void TraceeProgram::printStatus() {
	m_log->debug("PID : {} State : {}", getPid(), getStateString());
}

// void TraceeProgram::addPendingBrkPnt(std::vector<std::string>& brk_pnt_str) {
// 	for(auto brk_pnt: brk_pnt_str) {
// 		m_breakpointMngr->addModuleBrkPnt(brk_pnt);
// 	}
// }

// #include "spdlog/fmt/fmt.h"

TraceeProgram* TraceeFactory::createTracee(pid_t tracee_pid, DebugType debug_type) {

	auto traceeMemory = new RemoteMemory(tracee_pid);
	auto cpuRegister = new Registers(tracee_pid);
	auto procMap = new ProcessMap(tracee_pid);

	auto debugOpts = new DebugOpts(tracee_pid);
	debugOpts->setRemoteMemory(traceeMemory)
		.setRegisters(cpuRegister)
		.setProcessMap(procMap);
	
	auto tracee_obj = new TraceeProgram(debug_type);
	tracee_obj->setDebugOpts(debugOpts);
		// ->setLogFile(string("hussain"));

	return tracee_obj;
}

void TraceeFactory::releaseTracee(TraceeProgram* tracee_obj) {
	m_cached_tracee.push_back(tracee_obj);
}

/*
pid_t m_pid();

DebugOpts* setPid(pid_t tracee_pid) {
	m_pid(tracee_pid);
}

DebugOpts* m_debug_opts = nullptr;

TraceeProgram* setDebugOpts(DebugOpts* debug_opts) {
	m_debug_opts = debug_opts;
	return this;
};
*/