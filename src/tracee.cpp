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
	m_state = TraceeState::SYSCALL;
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
		case TraceeState::SYSCALL:
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

void TraceeProgram::processPtraceEvent(TraceeEvent event, TrapReason trap_reason) {
	// this function processes "PTRACE_EVENT stops" event
	if (trap_reason.status == TrapReason::CLONE ||
		trap_reason.status == TrapReason::FORK || 
		trap_reason.status == TrapReason::VFORK ) {
		m_debugger->addChildTracee(trap_reason.pid);
		m_log->trace("CLONE/FORK/VFORK");
		contExecution();
	} else if( trap_reason.status == TrapReason::EXEC) {
		m_log->trace("EXEC");
		contExecution();
	} else if( trap_reason.status == TrapReason::EXIT ) {
		// toStateExited();
		m_log->trace("EXIT");
		contExecution();
	} else if(trap_reason.status == TrapReason::SYSCALL) {
		m_log->trace("SYSCALL");
		// this state mean the tracee execution is handed to the
		// kernel for syscall process, 
		// NOTE: OS has not clear way to
		// distingish if the call is syscall enter or exit
		// and its debugger responsibity to track it
		contExecution();
	} else {
		m_log->warn("Not sure why we have stopped!");
		contExecution(event.signaled.signal);
	}
}

void TraceeProgram::processINITState() {
	m_log->info("Initial Stop, prepaing the tracee!");
	
	auto tracee_flags =  PTRACE_O_TRACESYSGOOD |
		PTRACE_O_TRACEEXEC    |
		PTRACE_O_TRACEEXIT;

	if (m_followFork) {
		tracee_flags |= PTRACE_O_TRACEFORK |
			PTRACE_O_TRACECLONE |
			PTRACE_O_TRACEVFORK;
	}

	int ret = ptrace(PTRACE_SETOPTIONS, getPid(), 0, tracee_flags);

	if (ret == -1) {
		m_log->error("Error occured while setting ptrace options while restarting the tracee!");
	}

	toStateRunning();

	// TODO : figure out the lift time of this param
	m_debug_opts->m_procMap->parse();
	
	// TODO : this is not appropriate point to inject
	// breakpoint in case of fork
	// when you fork the breakpoints which are put before
	// are already in place, so we only need to inject
	// which are pending
	m_breakpointMngr->inject();

	contExecution();
}

void TraceeProgram::processRUNState(TraceeEvent event, TrapReason trap_reason) {
	switch (event.type) {
		case TraceeEvent::EXITED:
			m_log->info("EXITED : process {} has exited!", getPid());
			toStateExited();
			break;
		case TraceeEvent::SIGNALED:
			m_log->critical("SIGNALLED : process {} terminated by a signal!!", getPid());
			toStateExited();
			break;
		case TraceeEvent::STOPPED:
			m_log->info("STOPPED : ");
			if(trap_reason.status == TrapReason::SYSCALL) {
				m_log->debug("SYSCALL ENTER");
				m_syscallMngr->onEnter();
				toStateSysCall();
			} else if(trap_reason.status == TrapReason::BREAKPOINT) {
				if (m_breakpointMngr->hasSuspendedBrkPnt()) {
					m_breakpointMngr->restoreSuspendedBreakpoint();
					contExecution();
				} else {

					// PC points to the next instruction after execution
					m_debug_opts->m_register->getGPRegisters();
					uintptr_t brk_addr = m_debug_opts->m_register->getPC();

					// this done to get previous the intruction which caused
					// the hit, and its architecture dependent, so this is
					// not the place to handle it
					brk_addr--;

					m_breakpointMngr->handleBreakpointHit(brk_addr);

					m_debug_opts->m_register->setPC(brk_addr);

					m_debug_opts->m_register->setGPRegisters();

					// delete prog_regs;
					singleStep();
				}
				// contExecution();
				break;
			}
			processPtraceEvent(event, trap_reason);
			break;
		case TraceeEvent::CONTINUED:
			m_log->debug("CONTINUED");
			contExecution();
			break;
		default:
			m_log->error("ERROR : UNKNOWN state {}", event.type);
			contExecution();
	}
}

void TraceeProgram::processSYSCALLState(TraceeEvent event, TrapReason trap_reason) {
	switch (event.type) {
		case TraceeEvent::EXITED:
			m_log->info("SYSCALL : EXITED : process {} has exited!", getPid());
			toStateExited();
			break;
		case TraceeEvent::SIGNALED:
			m_log->critical("SYSCALL : SIGNALLED : process {} terminated by a signal!!", getPid());
			toStateExited();
			break;
		case TraceeEvent::STOPPED:
			if(trap_reason.status == TrapReason::SYSCALL) {
				m_log->info("SYSCALL : EXIT");
				// change the state once we have process the event
				m_syscallMngr->onExit();
				toStateRunning();
			}
			processPtraceEvent(event, trap_reason);
			break;
		default:
			m_log->error("SYSCALL : ERROR : UNKNOWN state {}", event.type);
			contExecution();
	}
}

void TraceeProgram::processState(TraceeEvent event, TrapReason trap_reason) {
	// restrict the changing of tracee state to this function only

	switch(m_state) {
		case UNKNOWN:
			 m_log->critical("FATAL : You cannot possibily be living in this state");
			break;
		case INITIAL_STOP:
			processINITState();
			break;
		case RUNNING:
			m_log->debug("RUNNING");
			processRUNState(event, trap_reason);
			break;
		case SYSCALL:
			/*
				DOCS :
				Syscall-enter-stop and syscall-exit-stop are indistinguishable
   				from each other by the tracer. The tracer needs to keep track of
   				the sequence of ptrace-stops in order to not misinterpret
   				syscall-enter-stop as syscall-exit-stop or vice versa. In
   				general, a syscall-enter-stop is always followed by syscall-exit-
   				stop, PTRACE_EVENT stop, or the tracee's death; no other kinds of
   				ptrace-stop can occur in between.

				thats the reason we have the process this again
			*/
			processSYSCALLState(event, trap_reason);
			break;
		default:
			m_log->error("FATAL : Undefined Tracee State", event.type);
			break;
	}
}

void TraceeProgram::addPendingBrkPnt(std::vector<std::string>& brk_pnt_str) {
	for(auto brk_pnt: brk_pnt_str) {
		m_breakpointMngr->addModuleBrkPnt(brk_pnt);
	}
}

// #include "spdlog/fmt/fmt.h"

TraceeProgram* TraceeFactory::createTracee(pid_t tracee_pid, DebugType debug_type) {

	auto traceeMemory = new RemoteMemory(tracee_pid);
	auto cpuRegister = new Registers(tracee_pid);
	auto procMap = new ProcessMap(tracee_pid);

	auto debugOpts = new DebugOpts(tracee_pid);
	debugOpts->setRemoteMemory(traceeMemory)
		.setRegisters(cpuRegister)
		.setProcessMap(procMap);
	
	auto syscallMngr = new SyscallManager();
	syscallMngr->setDebugOpts(debugOpts);
	
	auto breakpointMngr = new BreakpointMngr();
	breakpointMngr->setDebugOpts(debugOpts);
	
	auto tracee_obj = new TraceeProgram(debug_type);
	tracee_obj->setDebugger(m_debugger)
		.setDebugOpts(debugOpts)
		.setSyscallMngr(syscallMngr)
		.setBreakpointMngr(breakpointMngr);
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