#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "debugger.hpp"
#include "memory.hpp"
#include "modules.hpp"


using namespace std;


Debugger::Debugger() {
	m_log = spdlog::get("main_log");
	
	m_tracee_factory = new TraceeFactory();
	m_syscallMngr = new SyscallManager();
	m_breakpointMngr = new BreakpointMngr();

}

void Debugger::addBreakpoint(std::vector<std::string>& _brk_pnt_str) {
	for(auto brk_pnt: _brk_pnt_str) {
		m_breakpointMngr->parseModuleBrkPnt(brk_pnt);
	}
}

int Debugger::spawn(vector<string>& cmdline) {

	// covert cmdline arguments to exev parameter type
	vector<const char *> args;
	
	args.reserve(cmdline.size() + 1);
	for(const auto& sp: cmdline) {
		args.push_back(sp.c_str());
	}
	// needed to terminate the args list
	args.push_back(nullptr);

	m_prog = &(cmdline.front());
	// remove the program path argument list
	// cmdline.erase(cmdline.begin());
	m_argv = &cmdline;
	m_log->info("Spawning process {}", m_prog->c_str());
	pid_t childPid = fork();
	
	if (childPid == -1) {
		m_log->error("fork() for tracee failed failed!");
		return -1;
	}

	if (childPid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, 0, 0)) {
			return -1;
		}
		
		int status_code = execvp(args[0], const_cast<char* const *>(args.data()));

		if (status_code == -1) {
			m_log->error("Process did not terminate correctly\n");
			exit(1);
		}

		m_log->debug("This line will not be printed if execvp() runs correctly\n");

		return 0;
	}

	m_log->debug("New Child spawed with PID {}", childPid);
	
	m_leader_tracee = addChildTracee(childPid);
	return 0;
}

TraceeProgram* Debugger::addChildTracee(pid_t child_tracee_pid) {
	if (child_tracee_pid == 0) {
		m_log->critical("FATAL : Whhaat tthhhee.... heelll...., child id cannot be zero! Not adding child to the list");
		return nullptr;
	} else {
		m_log->debug("New child {} is added to tracee list!", child_tracee_pid);
		auto trace_flag = DebugType::DEFAULT;
		if(m_traceSyscall) {
			trace_flag = DebugType::SYSCALL;
		}
		auto tracee_obj = m_tracee_factory->createTracee(child_tracee_pid, trace_flag);
		// tracee_obj->setDebugger(this);
		
		if (m_followFork)
			tracee_obj->followFork();
		
		// tracee_obj->addPendingBrkPnt(brk_pnt_str);

		m_Tracees.insert(make_pair(child_tracee_pid, tracee_obj));
		return tracee_obj;
	}
}

void Debugger::dropChildTracee(TraceeProgram* child_tracee) {
	m_log->debug("Dropping child tracee PID : {}", child_tracee->getPid());
 	m_Tracees.erase(child_tracee->getPid());
	m_tracee_factory->releaseTracee(child_tracee);
}

void Debugger::printAllTraceesInfo() {
	m_log->debug("Tracee state : ");
	TraceeProgram *tc_info = nullptr;
	for (auto i = m_Tracees.begin(); i != m_Tracees.end(); i++) {
		// m_log->debug("ID : {}", i->first);
		tc_info = i->second;
		tc_info->printStatus();
	}
}

bool Debugger::isBreakpointTrap(siginfo_t* info) {
	// m_log->debug("BK test signal code : {}", info->si_code);

	switch (info->si_code) {
	//one of these will be set if a breakpoint was hit
	case SI_KERNEL:
		m_log->trace("Breakpoint TRAP : KERNEL");
	case TRAP_BRKPT:
		m_log->trace("Breakpoint TRAP : Software");
		return true;
	case TRAP_TRACE:
		//this will be set if the signal was sent by single stepping
		m_log->trace("Breakpoint : TRAP_TRACE, possibly due to single stepping!");
		return true;
	default:
		m_log->error("Unknown SIGTRAP code {}", info->si_code);
	}
	return false;
}

/**
 * This function adds more details for the reason why the tracee was stopped.
 * Currently we are only Processing TrapReason::STOPPED as we move further
 * we will be adding more details to the trap reason.
*/
TrapReason Debugger::getTrapReason(TraceeEvent event, TraceeProgram* tracee_info) {
	pid_t new_pid = -1;
	pid_t pid_sig = tracee_info->getPid();

	TrapReason trap_reason = { TrapReason::INVALID, -1 };
	trap_reason.pid = pid_sig;
	if(event.type == TraceeEvent::STOPPED && event.stopped.signal == SIGTRAP) {
		if (PT_IF_CLONE(event.stopped.status)) {
			m_log->trace("SIGTRAP : CLONE");
			new_pid = 0;
			int pt_ret = ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
			// m_log->trace("SIGTRAP : PT CLONE : ret {}");
			trap_reason.status = TrapReason::CLONE;
			trap_reason.pid = new_pid;
		} else if (PT_IF_EXEC(event.stopped.status)) {
			m_log->trace("SIGTRAP : Exec");
			trap_reason.status = TrapReason::EXEC;
			trap_reason.pid = -1;
		} else if (PT_IF_EXIT(event.stopped.status)) {
			m_log->trace("SIGTRAP : Exit");
			trap_reason.status = TrapReason::EXIT;
			trap_reason.pid = -1;
		} else if (PT_IF_FORK(event.stopped.status)) {
			m_log->trace("SIGTRAP : Fork");
			new_pid = 0;
			int pt_ret = ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
			trap_reason.status = TrapReason::FORK;
			trap_reason.pid = new_pid;
		} else if (PT_IF_VFORK(event.stopped.status)) {
			m_log->trace("SIGTRAP : VFork");
			new_pid = 0;
			// Get the PID of the new process
			int pt_ret = ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
			trap_reason.status = TrapReason::VFORK;
			trap_reason.pid = new_pid;
		} else {
			if(!tracee_info->isInitialized()) {
				siginfo_t sig_info = {0};
				ptrace(PTRACE_GETSIGINFO, pid_sig, nullptr, &sig_info);
				if (isBreakpointTrap(&sig_info)) {
					trap_reason.status = TrapReason::BREAKPOINT;
					trap_reason.pid = pid_sig;
					m_log->trace("SIGTRAP : TID [{}] Breakpoint was hit !", trap_reason.pid);
				} else {
					m_log->warn("SIGTRAP : Couldn't Find Why are we trapped! Need to handle this!");
				}
			}
		}
	} else if (event.type == TraceeEvent::STOPPED && PT_IF_SYSCALL(event.stopped.signal)) {
		m_log->trace("SIGTRAP : SYSCALL");
		trap_reason.status = TrapReason::SYSCALL;
		trap_reason.pid = pid_sig;
	} else if (event.type == TraceeEvent::STOPPED && !tracee_info->isInitialized()) {
		siginfo_t sig_info = {0};
		/**
		 * sig_info_t has following important field for our purpose:
		 * 
		 * si_signo - is the signal number which has been delivered and has
		 * triggered this signal handler
		 * 
		 * si_code - is a value indicating why this signal was sent.
		*/
		
		ptrace(PTRACE_GETSIGINFO, pid_sig, nullptr, &sig_info);
		
		switch (event.stopped.signal) {
		case SIGSEGV:
			m_log->warn("That's right! Segfault, Reason: {} !", sig_info.si_code);
			break;
		case SIGILL:
			m_log->warn("Illegal Instruction!");
			break;
		case SIGKILL:
			m_log->warn("Killed!");
			break;
		default:
			m_log->warn("This STOP Signal not understood by us! Code : {}", sig_info.si_code);
			break;
		}
	} else {
		m_log->debug("Not a stop signal!");
	}
	return trap_reason;
}

void Debugger::attach(pid_t tracee_pid) {

	attachThread(tracee_pid);
	auto traceeProgram = getTracee(tracee_pid);
	traceeProgram->getDebugOpts()->m_procMap->list_child_threads();
	
	auto child_pids = traceeProgram->getDebugOpts()->m_procMap->m_child_thread_pids;

	for (auto iter = child_pids.begin() ; iter != child_pids.end(); ++iter) {
		pid_t child_pid = *iter;
		m_log->info("Child pid {}", child_pid);
		attachThread(child_pid);
	}
}

void Debugger::attachThread(pid_t tracee_pid) {
	auto tracee_obj = getTracee(tracee_pid);
	
	if (tracee_obj != nullptr) {
		// this means we are already tracing this tracee
		return;
	}

	int pt_ret = ptrace(PTRACE_ATTACH, tracee_pid, 0, 0);

	if (pt_ret == 0) {
		m_log->trace("Attach successful for pid : {}", tracee_pid);
		TraceeProgram* traceeProg = addChildTracee(tracee_pid);
		traceeProg->toAttach();
	} else {
		m_log->trace("Attach failed for pid {} reason {}", tracee_pid, pt_ret);
	}
}

TraceeProgram* Debugger::getTracee(pid_t tracee_pid) {
	auto tracee_iter = m_Tracees.find(tracee_pid);
	if (tracee_iter != m_Tracees.end()) {
		// tracee is found, its under over management
		return tracee_iter->second;
	} else {
		m_log->info("Tracee not found!");
		return nullptr;
	}
}

bool Debugger::eventLoop() {
		
	DebugOpts* debug_opts = nullptr; 
	TraceeProgram *traceeProgram;
	siginfo_t pt_sig_info = {0};
	TraceeEvent event;
	TraceeEvent invalid_event = TraceeEvent();

	while(!m_Tracees.empty()) {
		m_log->debug("------------------------------");
		pt_sig_info.si_pid = 0;	
		traceeProgram = nullptr;
		event = invalid_event;
		debug_opts = nullptr;
		printAllTraceesInfo();

		int ret_wait = waitid(
			P_ALL, 0, 
			&pt_sig_info,
			WEXITED | WSTOPPED | WCONTINUED | WNOWAIT
		);

		if (ret_wait == -1) {
			m_log->critical("waitid failed!");
			exit(-1);
		}
		
		pid_t pid_sig = pt_sig_info.si_pid;
		if (pid_sig == 0) {
			m_log->warn("Special Case of waitid(), please handle it!");
			exit(-1);
		}

		m_log->info("Signaled Pid : {} Signal Code : {}", pid_sig, pt_sig_info.si_code);

		auto tracee_iter = m_Tracees.find(pid_sig);
		if (tracee_iter != m_Tracees.end()) {
			// tracee is found, its under over management
			traceeProgram = tracee_iter->second;
		} else {
			m_log->info("Tracee not found!");
			traceeProgram = nullptr;
		}
		
		if (traceeProgram == nullptr) {
		  /**
			* It is possible that this PID is not under our management,
			* so now we have to check if any of our tracees have an
			* event for us. We are no longer going to receieve signal from
			* the `waitid()` as that may infinitely give us the same PID.
			* However, the PID that it is reporting could be a child from
			* a `fork()` event from one of our debuggees, and to get that
			* `fork()` event we have to "look ahead" in the signal queue
			* by non-blocking checking for signals from all of our
			* tracees.
			*
			* This is designed for the very real case as such:
			*
			* signal_queue = [
			*    STOP event from new child,
			*    TRAP event from tracee telling us it forked the child,
			* ]
			*
			* If we do not do this look ahead, the debugger will just
			* infinitely loop on `waitid()` and never observe a PID
			* under our control.
			*
			* It is also possible that we got a spurious `waitid()`
			* indicating the PID of _another_ [`Debugger`] instance had
			* an event. In this case, none of our tracees will have a
			* signal, and we'll just go back to `waitid()` without doing
			* anything. There's non-zero overhead to this, but I don't
			* think there is any other way to implement this without pidfd
			* which we are not using as it is too modern of a feature for
			* the targets we want to support.
			*/

			m_log->info("Tracee is not under over management");
			
			// reset the current processed tracee info
			event = invalid_event;

			// we are not sure which pid has caused this issue
			pid_sig = -1;
			bool found_event = false;
			
			for (auto i = m_Tracees.begin(); i != m_Tracees.end(); i++) {
				// Go through all known tracees looking for events
				pid_t tracee_pid = i->first;
				TraceeEvent ts_event = get_wait_event(tracee_pid);
				traceeProgram = i->second;
				m_log->debug("Inspecting ");
				traceeProgram->printStatus();
				ts_event.print();
				if (ts_event.isValidEvent()) {
					found_event = true;
					m_log->debug("Event from PID : {}", tracee_pid);
					pid_sig = tracee_pid;
					traceeProgram = m_Tracees[pid_sig];
					event = ts_event;
					break;
				}
			}
			if(!found_event) {
				m_log->critical("No tracee with event found! This should not happend, handle it!");
			}
		} else {
			event = get_wait_event(pid_sig);
		}

		if (!traceeProgram) {
			m_log->critical("Tracee cannot be null!");
			continue;
		}

		TrapReason trap_reason = getTrapReason(event, traceeProgram);
		
		// traceeProgram->processState(event, trap_reason);
		// processTraceeState(tracee_info, trap_reason);

		auto tracee_flags = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;
		int ret = -1;

		switch(traceeProgram->m_state) {
		case TraceeState::UNKNOWN:
			 m_log->critical("FATAL : You cannot possibily be living in this state");
			break;
		case TraceeState::ATTACH:
			if (event.type == TraceeEvent::STOPPED) {
				m_log->info("Thread has stopped!");
				// traceeProgram->toStateRunning();
				// traceeProgram->contExecution();
			} else {
				m_log->info("Thread hasn't stopped yet!");
			}
			// don't put the break statement here, its 
			// intentionally left behind.
		case TraceeState::INITIAL_STOP:
			m_log->info("Initial Stop, prepaing the tracee!");
			

			if (m_followFork) {
				tracee_flags |= PTRACE_O_TRACEFORK |
					PTRACE_O_TRACECLONE |
					PTRACE_O_TRACEVFORK;
			}

			ret = ptrace(PTRACE_SETOPTIONS, pid_sig, 0, tracee_flags);

			if (ret == -1) {
				m_log->error("Error occured while setting ptrace options while restarting the tracee!");
			}

			traceeProgram->toStateRunning();

			// TODO : figure out the lifetime of this param
			traceeProgram->getDebugOpts()->m_procMap->parse();
			
			// TODO : this is not appropriate point to injectrea
			// breakpoint in case of fork
			// when you fork the breakpoints which are put before
			// are already in place, so we only need to inject
			// which are pending
			m_breakpointMngr->inject(traceeProgram->getDebugOpts());

			traceeProgram->contExecution();
			break;
		case TraceeState::BREAKPOINT_HIT:
			// this state is the final state of breakpoint handling
			// we either restore the breakpoint or continue without
			// restoring it.
			if(event.type == TraceeEvent::STOPPED && trap_reason.status == TrapReason::BREAKPOINT) {
				debug_opts = traceeProgram->getDebugOpts();
					
				// debug_opts->m_register->getGPRegisters();
				m_breakpointMngr->restoreSuspendedBreakpoint(debug_opts);
				traceeProgram->toStateRunning();
				traceeProgram->contExecution();
			} else {
				m_log->error("State transistion is invalid!");
			}

			break;
		case TraceeState::RUNNING:

			m_log->debug("RUNNING");
			switch (event.type) {
			case TraceeEvent::EXITED:
				m_log->info("EXITED : process {} has exited!", pid_sig);
				traceeProgram->toStateExited();
				break;
			case TraceeEvent::SIGNALED:
				m_log->critical("SIGNALLED : process {} terminated by a signal!!", pid_sig);
				traceeProgram->toStateExited();
				break;
			case TraceeEvent::STOPPED:
				m_log->info("STOPPED : ");
				if (trap_reason.status == TrapReason::CLONE ||
					trap_reason.status == TrapReason::FORK || 
					trap_reason.status == TrapReason::VFORK ) {
					m_log->trace("CLONE/FORK/VFORK");
					// you will be getting this event when you are not following
					// system call event
					// m_log->error("You shouldn't be getting this event!");
					TraceeProgram* tracee_prog = addChildTracee(trap_reason.pid);
					if (trap_reason.status == TrapReason::CLONE) {
						// attach(trap_reason.pid);
						tracee_prog->setThreadGroupid(m_leader_tracee->getPid());
						m_log->trace("New Thead is created with pid {} and tgid {}!", tracee_prog->getPid(), tracee_prog->getThreadGroupid());
					}
				} else if( trap_reason.status == TrapReason::EXEC) {
					m_log->trace("EXEC: new child has been added please hand over to a different debugger");
					// New child has been added which is completed different from our
					// process so probablity create new Debugger instance and hand 
					// this child to that instance
					// ProcessMap m_procMap(pid_sig);
					// m_procMap.parse();
					// m_procMap.print();
				} else if( trap_reason.status == TrapReason::EXIT ) {
					// toStateExited();
					m_log->trace("EXIT");
					// traceeProgram->contExecution();
				} else  if(trap_reason.status == TrapReason::SYSCALL) {
					// this state mean the tracee execution is handed to the
					// kernel for syscall process, 
					// NOTE: OS has not clear way to
					// distingish if the call is syscall enter or exit
					// and its debugger responsibity to track it
					m_log->debug("SYSCALL ENTER");
					m_syscallMngr->onEnter(traceeProgram->getDebugOpts());
					traceeProgram->toStateSysCall();
				} else if(trap_reason.status == TrapReason::BREAKPOINT) {
					/**
					 * To please breakpoint we have to place breakpoint inst
					 * on the address. When it inst is executed out code is 
					 * called
					 * Once we get the breakpoint hit we restore the brk inst
					 * with the original inst and change the EIP to one inst
					 * back to the original inst.
					 * We do single step and only execute one inst and at
					 * this point you have the option to restore the breakpoint
					 * or not.
					 * But after breakpoint is hit you alway have to do single
					 * step wheather you want to restore the breakpoint or not.
					 * Not sure why!
					 */
					// traceeProgram->toStateBreakpoint();
					debug_opts = traceeProgram->getDebugOpts();
					
					debug_opts->m_register->getGPRegisters();
					uintptr_t brk_addr = debug_opts->m_register->getPC();

					if(prev_brk_addr == brk_addr && prev_pid != debug_opts->getPid()) {
						m_log->warn("hit the edge case!");
						break;
					}

					// if (m_breakpointMngr->hasSuspendedBrkPnt(debug_opts->m_pid)) {
					// 	prev_brk_addr = 0;
					// 	m_breakpointMngr->restoreSuspendedBreakpoint(debug_opts);
					// 	traceeProgram->contExecution();
					// 	break;
					// } else {
						prev_brk_addr = brk_addr;
						prev_pid = debug_opts->getPid();
						// PC points to the next instruction after execution

						// this done to get previous the intruction which caused
						// the hit, and its architecture dependent, so this is
						// not the place to handle it
						brk_addr--;
						// debug_opts->m_register->print();
						m_breakpointMngr->handleBreakpointHit(debug_opts, brk_addr);

						debug_opts->m_register->setPC(brk_addr);

						debug_opts->m_register->setGPRegisters();
						traceeProgram->toStateBreakpoint();
						// debug_opts->m_register->print();
						traceeProgram->singleStep();
						// traceeProgram->contExecution();
						break;
					// }
					break;
				} else {
					m_log->warn("Not sure why we have stopped!");
					traceeProgram->contExecution(event.signaled.signal);
					break;
				}
				traceeProgram->contExecution();
				// this function processes "PTRACE_EVENT stops" event
				break;
			case TraceeEvent::CONTINUED:
				m_log->debug("CONTINUED");
				traceeProgram->contExecution();
				break;
			default:
				m_log->error("ERROR : UNKNOWN state {}", event.type);
				traceeProgram->contExecution();
			}
			break;
		case TraceeState::IN_SYSCALL:
			m_log->debug("State SYSCALL");
			/**
			* DOCS :
			* Syscall-enter-stop and syscall-exit-stop are indistinguishable
			* from each other by the tracer. The tracer needs to keep track of
			* the sequence of ptrace-stops in order to not misinterpret
			* syscall-enter-stop as syscall-exit-stop or vice versa. In
			* general, a syscall-enter-stop is always followed by syscall-exit-
			* stop, PTRACE_EVENT stop, or the tracee's death; no other kinds of
			* ptrace-stop can occur in between.
			* 
			* thats the reason we have the process this again
			*/
			switch (event.type) {
			case TraceeEvent::EXITED:
				m_log->info("SYSCALL : EXITED : process {} has exited!", pid_sig);
				traceeProgram->toStateExited();
				break;
			case TraceeEvent::SIGNALED:
				m_log->critical("SYSCALL : SIGNALLED : process {} terminated by a signal, Possibly in kernel space!!", pid_sig);
				traceeProgram->toStateExited();
				break;
			case TraceeEvent::STOPPED:

				if(trap_reason.status == TrapReason::SYSCALL) {
					m_log->info("SYSCALL EXIT");
					// change the state once we have process the event
					m_syscallMngr->onExit(traceeProgram->getDebugOpts());
					traceeProgram->toStateRunning();
				} else if (trap_reason.status == TrapReason::CLONE ||
				// this function processes "PTRACE_EVENT stops" event
					trap_reason.status == TrapReason::FORK || 
					trap_reason.status == TrapReason::VFORK ) {
					// this can happend when you are dealing with fork/vfork/clone
					// system call
					m_log->trace("SYSCALL: CLONE/FORK/VFORK");
					TraceeProgram* tracee_prog = addChildTracee(trap_reason.pid);
					if (trap_reason.status == TrapReason::CLONE) {
						// attach(trap_reason.pid);
						tracee_prog->setThreadGroupid(m_leader_tracee->getPid());
						m_log->trace("New Thead is created with pid {} and tgid {}!", tracee_prog->getPid(), tracee_prog->getThreadGroupid());
					}
					// traceeProgram->contExecution();
				} else if( trap_reason.status == TrapReason::EXEC) {
					m_log->trace("SYSCALL: EXEC");
					// traceeProgram->contExecution();
				} else if( trap_reason.status == TrapReason::EXIT ) {
					// toStateExited();
					m_log->trace("SYSCALL: EXIT");
					// traceeProgram->contExecution();
				} else {
					m_log->warn("SYSCALL: Not sure why we have stopped!");
					traceeProgram->contExecution(event.signaled.signal);
					break;
				}
				traceeProgram->contExecution();
				break;
			default:
				m_log->error("SYSCALL : ERROR : UNKNOWN state {}", event.type);
			
		}
			break;
		default:
			m_log->error("FATAL : Undefined Tracee State", event.type);
			break;
		}
		if (traceeProgram->hasExited()) {
			dropChildTracee(traceeProgram);				
		}

	}
	m_breakpointMngr->printStats();
	m_log->info("There are not tracee left to debug. Exiting!");
	return true;
}

