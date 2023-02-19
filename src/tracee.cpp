#include "tracee.hpp"

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
		spdlog::trace("contExec Tracee CONT");
		pt_ret = ptrace(PTRACE_CONT, m_pid, 0L, sig);
	} else if (debugType & DebugType::SYSCALL) {
		spdlog::trace("contExec Tracee Syscall");
		pt_ret = ptrace(PTRACE_SYSCALL, m_pid, 0L, sig);
	} else if (debugType & DebugType::SINGLE_STEP) {
		spdlog::trace("contExec single step");
		pt_ret = ptrace(PTRACE_SINGLESTEP, m_pid, 0L, sig);
	}

	if(pt_ret < 0) {
		spdlog::error("ptrace continue call failed! Err code : {} ", pt_ret);
	}
	return pt_ret;
}

int TraceeProgram::singleStep() {
	int pt_ret = ptrace(PTRACE_SINGLESTEP, m_pid, 0L, 0);
	if(pt_ret < 0) {
		spdlog::error("failed to single step! Err code : {} ", pt_ret);
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
	};
}

void TraceeProgram::printStatus() {
	spdlog::debug("PID : {} State : {}", m_pid, getStateString());
}

void TraceeProgram::processPtraceEvent(TraceeEvent event, TrapReason trap_reason) {
	// this function processes "PTRACE_EVENT stops" event
	if (trap_reason.status == TrapReason::CLONE ||
		trap_reason.status == TrapReason::FORK || 
		trap_reason.status == TrapReason::VFORK ) {
		m_debugger.addChildTracee(trap_reason.pid);
		spdlog::trace("CLONE/FORK/VFORK");
		contExecution();
	} else if( trap_reason.status == TrapReason::EXEC) {
		spdlog::trace("EXEC");
		contExecution();
	} else if( trap_reason.status == TrapReason::EXIT ) {
		// toStateExited();
		spdlog::trace("EXIT");
		contExecution();
	} else if(trap_reason.status == TrapReason::SYSCALL) {
		spdlog::trace("SYSCALL");
		// this state mean the tracee execution is handed to the
		// kernel for syscall process, 
		// NOTE: OS has not clear way to
		// distingish if the call is syscall enter or exit
		// and its debugger responsibity to track it
		contExecution();
	} else {
		spdlog::warn("Not sure why we have stopped!");
		contExecution(event.signaled.signal);
	}
}

void TraceeProgram::processINITState() {
	spdlog::info("Initial Stop, prepaing the tracee!");
	int ret = ptrace(PTRACE_SETOPTIONS, m_pid, 0, 
		PTRACE_O_TRACECLONE   |
		PTRACE_O_TRACEEXEC    |
		PTRACE_O_TRACEEXIT    |
		PTRACE_O_TRACEFORK    |
		PTRACE_O_TRACESYSGOOD |
		PTRACE_O_TRACEVFORK
	);

	if (ret == -1) {
		spdlog::error("Error occured while setting ptrace options while restarting the tracee!");
	}

	toStateRunning();

	// TODO : figure out the lift time of this param
	m_procMap->parse();
	
	// TODO : this is not appropriate point to inject
	// breakpoint in case of fork
	// when you fork the breakpoints which are put before
	// are already in place, so we only need to inject
	// which are pending
	m_breakpointMngr.inject();
	contExecution();
}

void TraceeProgram::processRUNState(TraceeEvent event, TrapReason trap_reason) {
	switch (event.type) {
		case TraceeEvent::EXITED:
			spdlog::info("EXITED : process {} has exited!", m_pid);
			toStateExited();
			break;
		case TraceeEvent::SIGNALED:
			spdlog::critical("SIGNALLED : process {} terminated by a signal!!", m_pid);
			toStateExited();
			break;
		case TraceeEvent::STOPPED:
			spdlog::info("STOPPED : ");
			if(trap_reason.status == TrapReason::SYSCALL) {
				toStateSysCall();
				spdlog::debug("SYSCALL ENTER");
				// printSyscall(m_pid);
			} else if(trap_reason.status == TrapReason::BREAKPOINT) {
				if (m_breakpointMngr.hasSuspendedBrkPnt()) {
					m_breakpointMngr.restoreSuspendedBreakpoint();
					contExecution();
				} else {

					// PC points to the next instruction after execution
					m_register.getGPRegisters();
					uintptr_t brk_addr = m_register.getPC();

					brk_addr--;

					m_breakpointMngr.handleBreakpointHit(brk_addr);

					m_register.setPC(brk_addr);

					m_register.setGPRegisters();

					// delete prog_regs;
					singleStep();
				}
				// contExecution();
				break;
			}
			processPtraceEvent(event, trap_reason);
			break;
		case TraceeEvent::CONTINUED:
			spdlog::debug("CONTINUED");
			contExecution();
			break;
		default:
			spdlog::error("ERROR : UNKNOWN state {}", event.type);
			contExecution();
	}
}

void TraceeProgram::processSYSCALLState(TraceeEvent event, TrapReason trap_reason) {
	switch (event.type) {
		case TraceeEvent::EXITED:
			spdlog::info("SYSCALL : EXITED : process {} has exited!", m_pid);
			toStateExited();
			break;
		case TraceeEvent::SIGNALED:
			spdlog::critical("SYSCALL : SIGNALLED : process {} terminated by a signal!!", m_pid);
			toStateExited();
			break;
		case TraceeEvent::STOPPED:
			if(trap_reason.status == TrapReason::SYSCALL) {
				spdlog::info("SYSCALL : EXIT");
				// change the state once we have process the event
				toStateRunning();
			}
			processPtraceEvent(event, trap_reason);
			break;
		default:
			spdlog::error("SYSCALL : ERROR : UNKNOWN state {}", event.type);
			contExecution();
	}
}

void TraceeProgram::processState(TraceeEvent event, TrapReason trap_reason) {
	// restrict the changing of tracee state to this function only

	switch(m_state) {
		case UNKNOWN:
			 spdlog::critical("FATAL : You cannot possibily be living in this state");
			break;
		case INITIAL_STOP:
			processINITState();
			break;
		case RUNNING:
			spdlog::debug("RUNNING");
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
			spdlog::error("FATAL : Undefined Tracee State", event.type);
			break;
	}
}

void TraceeProgram::addPendingBrkPnt(std::vector<std::string>& brk_pnt_str) {
	for(auto brk_pnt: brk_pnt_str) {
		m_breakpointMngr.addModuleBrkPnt(brk_pnt);
	}
}
