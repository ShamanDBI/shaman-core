#include "debugger.hpp"
#include "modules.hpp"
#include "tracee.hpp"
#include "breakpoint.hpp"


Debugger::Debugger(TargetDescription& _target_desc): m_target_desc(_target_desc) {
	m_log = spdlog::get("main_log");
	
	m_tracee_factory = new TraceeFactory();
	m_syscallMngr = new SyscallManager();
	m_breakpointMngr = new BreakpointMngr(m_target_desc);

}

void Debugger::addBreakpoint(std::vector<std::string>& _brk_pnt_str) {
	for(auto brk_pnt: _brk_pnt_str) {
		m_breakpointMngr->parseModuleBrkPnt(brk_pnt);
	}
}

int Debugger::spawn(std::vector<std::string>& cmdline) {

	// covert cmdline arguments to exev parameter type
	std::vector<const char *> args;
	
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
	m_log->info("Spawning new process : {}", m_prog->c_str());
	pid_t childPid = fork();
	
	if (childPid == -1) {
		m_log->error("fork() for tracee failed!");
		return -1;
	}

	if (childPid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, 0, 0)) {
			m_log->error("PTRACE_TRACEME failed!");
			return -1;
		}
		
		int status_code = execvp(args[0], const_cast<char* const *>(args.data()));

		if (status_code == -1) {
			m_log->error("Process did not terminate correctly");
			exit(1);
		}

		m_log->error("error while spawning new process with `execvp`");

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
			trace_flag = DebugType::TRACE_SYSCALL;
		}
		auto tracee_obj = m_tracee_factory->createTracee(child_tracee_pid, trace_flag, m_target_desc);
		// tracee_obj->setDebugger(this);
		
		if (m_followFork)
			tracee_obj->followFork();
		
		// tracee_obj->addPendingBrkPnt(brk_pnt_str);

		m_Tracees.insert(std::make_pair(child_tracee_pid, tracee_obj));
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
void Debugger::getTrapReason(DebugEventPtr& debug_event, TraceeProgram* tracee_info) {
	pid_t new_pid = -1;
	pid_t signalled_pid = tracee_info->getPid();
	TraceeEvent& event = debug_event->event;

	TrapReason& trap_reason = debug_event->reason;
	trap_reason.pid = signalled_pid;

	if(event.type == TraceeEvent::STOPPED && event.stopped.signal == SIGTRAP) {
		if (PT_IF_CLONE(event.stopped.status)) {
			m_log->trace("SIGTRAP : CLONE");
			new_pid = 0;
			int pt_ret = ptrace(PTRACE_GETEVENTMSG, signalled_pid, 0, &new_pid);
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
			int pt_ret = ptrace(PTRACE_GETEVENTMSG, signalled_pid, 0, &new_pid);
			trap_reason.status = TrapReason::FORK;
			trap_reason.pid = new_pid;
		} else if (PT_IF_VFORK(event.stopped.status)) {
			m_log->trace("SIGTRAP : VFork");
			new_pid = 0;
			// Get the PID of the new process
			int pt_ret = ptrace(PTRACE_GETEVENTMSG, signalled_pid, 0, &new_pid);
			trap_reason.status = TrapReason::VFORK;
			trap_reason.pid = new_pid;
		} else {
			if(!tracee_info->isInitialized()) {
				siginfo_t sig_info = {0};
				ptrace(PTRACE_GETSIGINFO, signalled_pid, nullptr, &sig_info);
				if (isBreakpointTrap(&sig_info)) {
					trap_reason.status = TrapReason::BREAKPOINT;
					trap_reason.pid = signalled_pid;
					m_log->trace("SIGTRAP : TID [{}] Breakpoint was hit !", trap_reason.pid);
				} else {
					m_log->warn("SIGTRAP : Couldn't Find Why are we trapped! Need to handle this!");
				}
			}
		}
	} else if (event.type == TraceeEvent::STOPPED && PT_IF_SYSCALL(event.stopped.signal)) {
		m_log->trace("SIGTRAP : SYSCALL");
		trap_reason.status = TrapReason::SYSCALL;
		trap_reason.pid = signalled_pid;
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
		trap_reason.status = TrapReason::ERROR;

		ptrace(PTRACE_GETSIGINFO, signalled_pid, nullptr, &sig_info);
		
		switch (event.stopped.signal) {
		case SIGSEGV:
			m_log->error("That's right! Segfault, Reason: {} !", sig_info.si_code);
			break;
		case SIGILL:
			m_log->error("Illegal Instruction!");
			break;
		case SIGKILL:
			m_log->error("Killed!");
			break;
		default:
			m_log->error("This STOP Signal not understood by us! Code : {}", sig_info.si_code);
			break;
		}
	} else {
		m_log->debug("Not a stop signal!");
	}
}

void Debugger::attach(pid_t tracee_pid) {

	m_log->info("Attaching to thread : {}", tracee_pid);
	attachThread(tracee_pid);
	auto traceeProgram = getTracee(tracee_pid);
	traceeProgram->getDebugOpts().m_procMap.list_child_threads();
	auto child_pids = traceeProgram->getDebugOpts().m_procMap.m_child_thread_pids;
	m_log->info("Attaching to child threads, No of threads {}", tracee_pid, child_pids.size());

	for (auto iter = child_pids.begin() ; iter != child_pids.end(); ++iter) {
		pid_t child_pid = *iter;
		m_log->info("Child pid {}", child_pid);
		attachThread(child_pid);
	}
}

void Debugger::attachThread(pid_t tracee_pid) {
	auto tracee_obj = getTracee(tracee_pid);
	
	if (tracee_obj != nullptr) {
		m_log->warn("We are already attached to pid : {}", tracee_pid);
		return;
	}

	int pt_ret = ptrace(PTRACE_ATTACH, tracee_pid, 0, 0);

	if (pt_ret == 0) {
		m_log->trace("Attach successful for pid : {}", tracee_pid);
		TraceeProgram* traceeProg = addChildTracee(tracee_pid);
		traceeProg->toAttach();
	} else {
		m_log->error("Failed to attach debugger to pid {}, reason {}", tracee_pid, pt_ret);
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

#include <set>

bool Debugger::eventLoop() {
		
	DebugOpts* debug_opts = nullptr; 
	TraceeProgram *traceeProgram;
	siginfo_t pt_sig_info = {0};
	// TraceeEvent event;
	// TrapReason trap_reason;
	DebugEventPtr debug_event(new DebugEvent());
	int ret_wait = -1;
	pid_t signalled_pid = 0;
	
	/**
	 * these variables was introduced because once we put the breakpoint event
	 * in queue we don't want to process it right away, we are waiting for
	 * the other breakpoint to complete the stepover and then process this
	 * pending breakpoint, so below three variable are using to achieve
	 * this usecase.
	 * I think we need a better way to deal with this issue. Because I want
	 * to signal specific set of breakpoint to be process and all the things
	 * in the queue.
	*/

	std::map<uintptr_t, std::queue<DebugEventPtr>> pending_thread_debug_event;
	// we have temporairly removed breakpoint at this location
	// which should be restored after stepping through the original instruction
	std::set<uintptr_t> active_breakpoint;
	std::queue<DebugEventPtr> pending_debug_events;
	
	bool processing_pending_event = false;
	uintptr_t brk_addr = 0;
	while(!m_Tracees.empty()) {
		m_log->debug("------------------------------");
		pt_sig_info.si_pid = 0;	
		traceeProgram = nullptr;
		debug_event->makeInvalid();
		debug_opts = nullptr;
		signalled_pid = 0;
		ret_wait = -1;

		printAllTraceesInfo();

		if (!pending_debug_events.empty()) {
			processing_pending_event = true;
			m_log->info("We have pending events. Pending {}", pending_debug_events.size());
			debug_event = std::move(pending_debug_events.front());
			pending_debug_events.pop();
			signalled_pid = debug_event->m_pid;
			debug_event->event.print();
			debug_event->reason.print();
			m_log->debug("Pending Signaled Pid {}", signalled_pid);
		} else {
			processing_pending_event = false;
			ret_wait = waitid(
				P_ALL, 0, 
				&pt_sig_info,
				WEXITED | WSTOPPED | WCONTINUED | WNOWAIT
			);

			if (ret_wait == -1) {
				m_log->critical("waitid failed!");
				exit(-1);
			}
			signalled_pid = pt_sig_info.si_pid;
			m_log->info("Signaled Pid : {} Signal Code : {}", signalled_pid, pt_sig_info.si_code);
		}
		
		if (signalled_pid == 0) {
			m_log->warn("Special Case of waitid(), please handle it!");
			exit(-1);
		}

		auto tracee_iter = m_Tracees.find(signalled_pid);
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
			debug_event->makeInvalid();

			// we are not sure which pid has caused this issue
			signalled_pid = -1;
			bool found_event = false;
			
			for (auto i = m_Tracees.begin(); i != m_Tracees.end(); i++) {
				// Go through all known tracees looking for events
				pid_t tracee_pid = i->first;
				get_wait_event(tracee_pid, debug_event);
				traceeProgram = i->second;
				m_log->debug("Inspecting ");
				traceeProgram->printStatus();
				debug_event->event.print();
				if (debug_event->event.isValidEvent()) {
					found_event = true;
					m_log->debug("Event from PID : {}", tracee_pid);
					signalled_pid = tracee_pid;
					traceeProgram = m_Tracees[signalled_pid];
					debug_event->m_pid = signalled_pid;
					break;
				}
			}
			if(!found_event) {
				// if this happens, and we are not handling ptrace events properly.
				// This mean we need to solve and Edge case. Its an OS level issue
				m_log->critical("No tracee with event found! This should not happend, handle it!");
				continue;
			}
		} else {
			if (!processing_pending_event) {
				get_wait_event(signalled_pid, debug_event);
				debug_event->m_pid = signalled_pid;
			}
		}

		if (!processing_pending_event) {
			getTrapReason(debug_event, traceeProgram);
		}

		// debug_event->print();
		
		auto tracee_flags = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;
		int ret = -1;

		switch(traceeProgram->m_state) {
		case TraceeState::UNKNOWN:
			 m_log->critical("FATAL : You cannot possibily be living in this state");
			break;
		case TraceeState::ATTACH:
			if (debug_event->event.type == TraceeEvent::STOPPED) {
				m_log->info("Thread has stopped!");
				// traceeProgram->toStateRunning();
				// traceeProgram->contExecution();
			} else {
				m_log->info("Thread hasn't stopped yet!");
			}
			// don't put the break statement here, its intentionally
			// left behind.
		case TraceeState::INITIAL_STOP:
			m_log->info("Initial Stop, prepaing the tracee!");

			if (m_followFork) {
				tracee_flags |= PTRACE_O_TRACEFORK |
					PTRACE_O_TRACECLONE |
					PTRACE_O_TRACEVFORK;
			}

			ret = ptrace(PTRACE_SETOPTIONS, signalled_pid, 0, tracee_flags);

			if (ret == -1) {
				m_log->error("Error occured while setting ptrace options while restarting the tracee!");
			}

			traceeProgram->toStateRunning();

			// TODO : figure out the lifetime of this param
			traceeProgram->getDebugOpts().m_procMap.parse();
			
			// TODO : this is not appropriate point to injectrea
			// breakpoint in case of fork
			// when you fork the breakpoints which are put before
			// are already in place, so we only need to inject
			// which are pending
			m_breakpointMngr->inject(traceeProgram->getDebugOpts());

			traceeProgram->contExecution();
			break;
		case TraceeState::BREAKPOINT_HIT:
			// This state is triggered because of the single step after breakpoint hit.
			// its the state is the final state of breakpoint handling we either restore
			// the breakpoint or continue without restoring it.
			
			debug_opts = &traceeProgram->getDebugOpts();
			debug_opts->m_register.fetch();

			if (traceeProgram->m_target_desc.m_cpu_arch == CPU_ARCH::AMD64) {
				AMD64Register& amdReg = reinterpret_cast<AMD64Register&>(debug_opts->m_register);
				brk_addr = amdReg.getBreakpointAddr();
			} else if (traceeProgram->m_target_desc.m_cpu_arch == CPU_ARCH::ARM32) {
				ARM32Register& armReg = reinterpret_cast<ARM32Register&>(debug_opts->m_register);
				brk_addr = armReg.getBreakpointAddr();
			} else if (traceeProgram->m_target_desc.m_cpu_arch == CPU_ARCH::ARM64) {
				ARM64Register& arm64Reg = reinterpret_cast<ARM64Register&>(debug_opts->m_register);
				brk_addr = arm64Reg.getBreakpointAddr();
			}

			m_log->debug("Breakpoint restore : 0x{:x} {:x}", traceeProgram->m_brkpnt_addr, brk_addr);
			
			if (traceeProgram->m_target_desc.m_cpu_arch == CPU_ARCH::ARM32) {
				std::unique_ptr<Breakpoint> ss_brkpt = std::move(traceeProgram->m_single_step_brkpnt);
				ss_brkpt->disable(traceeProgram->getDebugOpts());
				ss_brkpt.reset();
			}
			// debug_event->print();
			if(debug_event->event.type == TraceeEvent::STOPPED 
				&& debug_event->reason.status == TrapReason::BREAKPOINT) {

				// ARM32 doesn't have ptrace single stepping, so we have to emulate one
				// by placing breakpoint on the next instruction. We will be here on the single
				// step, at this stage we will restore the original breakpoint and remove the
				// single-step breakpoint 
				
				m_breakpointMngr->restoreSuspendedBreakpoint(traceeProgram->getDebugOpts());
				active_breakpoint.erase(traceeProgram->m_brkpnt_addr);
				m_log->info("Breakpoint handled 0x{:x}", traceeProgram->m_brkpnt_addr);
				
				if(!pending_thread_debug_event[traceeProgram->m_brkpnt_addr].empty()) {
					// Once we have handled this breakpoint we want to see if there
					// is another thread which has been block because of same breakpoint
					// in that case de-queue the event and put it in the active process queue
					// move the event from per-thread pending queue to the queue 
					// which will start processing the event
					m_log->debug("We have pending breakpoint to process!");
					pending_debug_events.push(std::move(pending_thread_debug_event[traceeProgram->m_brkpnt_addr].front()));
					pending_thread_debug_event[traceeProgram->m_brkpnt_addr].pop();
				}
				traceeProgram->m_brkpnt_addr = 0;
				traceeProgram->m_active_brkpnt = nullptr;
				// continue the execution
				traceeProgram->toStateRunning();
				traceeProgram->contExecution(0);
			} else {
				m_log->error("Processing and Invalid Event! State transistion is invalid!");
			}

			break;
		case TraceeState::RUNNING:

			m_log->debug("RUNNING");
			switch (debug_event->event.type) {
			case TraceeEvent::EXITED:
				m_log->info("EXITED : process {} has exited!", signalled_pid);
				traceeProgram->toStateExited();
				break;
			case TraceeEvent::SIGNALED:
				m_log->critical("SIGNALLED : process {} terminated by a signal {} !!", signalled_pid, debug_event->event.signaled.signal);
				traceeProgram->toStateExited();
				break;
			case TraceeEvent::STOPPED:
				m_log->info("STOPPED : ");
				if (debug_event->reason.status == TrapReason::CLONE ||
					debug_event->reason.status == TrapReason::FORK ||
					debug_event->reason.status == TrapReason::VFORK ) {
					m_log->trace("CLONE/FORK/VFORK");
					// you will be getting this event when you are not following
					// system call event
					// m_log->error("You shouldn't be getting this event!");
					TraceeProgram* tracee_prog = addChildTracee(debug_event->reason.pid);
					if (debug_event->reason.status == TrapReason::CLONE) {
						// attach(debug_event->reason.pid);
						tracee_prog->setThreadGroupid(m_leader_tracee->getPid());
						m_log->trace("New Thead is created with pid {} and tgid {}!", tracee_prog->getPid(), tracee_prog->getThreadGroupid());
					}
				} else if( debug_event->reason.status == TrapReason::EXEC) {
					m_log->trace("EXEC: new child has been added please hand over to a different debugger");
					// New child has been added which is completed different from our
					// process so probablity create new Debugger instance and hand 
					// this child to that instance
					// ProcessMap m_procMap(signalled_pid);
					// m_procMap.parse();
					// m_procMap.print();
				} else if( debug_event->reason.status == TrapReason::EXIT ) {
					// toStateExited();
					m_log->trace("EXIT");
					// traceeProgram->contExecution();
				} else  if(debug_event->reason.status == TrapReason::SYSCALL) {
					// this state mean the tracee execution is handed to the
					// kernel for syscall process, 
					// NOTE: OS has not clear way to
					// distingish if the call is syscall enter or exit
					// and its debugger responsibity to track it
					m_log->debug("SYSCALL ENTER");
					m_syscallMngr->onEnter(*traceeProgram);
					traceeProgram->toStateSysCall();
				} else if(debug_event->reason.status == TrapReason::BREAKPOINT) {
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
					debug_opts = &traceeProgram->getDebugOpts();
					debug_opts->m_register.fetch();
					
					uintptr_t brk_addr = 0;

					if (traceeProgram->m_target_desc.m_cpu_arch == CPU_ARCH::AMD64) {
						AMD64Register& amdReg = reinterpret_cast<AMD64Register&>(debug_opts->m_register);
						brk_addr = amdReg.getBreakpointAddr();
					} else if (traceeProgram->m_target_desc.m_cpu_arch == CPU_ARCH::ARM32) {
						ARM32Register& armReg = reinterpret_cast<ARM32Register&>(debug_opts->m_register);
						brk_addr = armReg.getBreakpointAddr();
					} else if (traceeProgram->m_target_desc.m_cpu_arch == CPU_ARCH::ARM64) {
						ARM64Register& armReg = reinterpret_cast<ARM64Register&>(debug_opts->m_register);
						brk_addr = armReg.getBreakpointAddr();
					}

					if(active_breakpoint.count(brk_addr) > 0) {
					//  prev_brk_addr == brk_addr && prev_pid != debug_opts->getPid()) {}
						m_log->info("Breakpoint stepover race condition!");
						m_log->info("{} pid is attempting to execute {} pid's breakpoint handler", debug_opts->getPid(), prev_pid);
						m_log->info("Breakpoint address 0x{:x}", brk_addr);
						// pending_debug_events.push(std::move(debug_event));
						pending_thread_debug_event[brk_addr].push(std::move(debug_event));
						debug_event = std::move(DebugEventPtr(new DebugEvent()));
						break;
					}

					traceeProgram->m_active_brkpnt = m_breakpointMngr->getBreakpointObj(brk_addr);
					traceeProgram->m_brkpnt_addr = brk_addr;

					active_breakpoint.insert(brk_addr);

					// prev_brk_addr = brk_addr;
					// prev_pid = debug_opts->getPid();
					// PC points to the next instruction after execution

					// this done to get previous the intruction which caused
					// the hit, and its architecture dependent, so this is
					// not the place to handle it
					// debug_opts->m_register->print();
					m_breakpointMngr->handleBreakpointHit(*debug_opts, brk_addr);

					if (traceeProgram->m_target_desc.m_cpu_arch == CPU_ARCH::AMD64) {
						AMD64Register& amdReg = reinterpret_cast<AMD64Register&>(debug_opts->m_register);
						amdReg.setProgramCounter(brk_addr);
						amdReg.update();
						traceeProgram->toStateBreakpoint();
						traceeProgram->singleStep();
					} else if (traceeProgram->m_target_desc.m_cpu_arch == CPU_ARCH::ARM32) {
						// TODO : Breakpoint support for ARM32 is work in progress
						ARM32Register& armReg = reinterpret_cast<ARM32Register&>(debug_opts->m_register);
						
						// uintptr_t next_inst_addr = 0;
						// if(armReg.isThumbMode()) {
						// 	next_inst_addr = brk_addr + 2;
						// } else {
						// 	next_inst_addr = brk_addr + 4;
						// }}
						// __builtin___clear_cache((char *)brk_addr, (char *)brk_addr + 1024);
						// auto ss_bkpt = std::unique_ptr<Breakpoint>(m_breakpointMngr->getBreakpointObj(brk_addr));
						// auto ss_bkpt = m_breakpointMngr->placeSingleStepBreakpoint(*debug_opts, next_inst_addr);
						// traceeProgram->m_single_step_brkpnt = std::move(ss_bkpt);
						// armReg.setProgramCounter(brk_addr);
						// armReg.update();
						traceeProgram->toStateRunning();
						// single stepping is not supported in ARM32 Linux Kernel
						traceeProgram->contExecution(0);
					} else if (traceeProgram->m_target_desc.m_cpu_arch == CPU_ARCH::ARM64) {
						traceeProgram->toStateBreakpoint();
						traceeProgram->singleStep();
					}
					
					// debug_opts->m_register->print();
					break;
				} else {
					m_log->warn("Not sure why we have stopped!");
					traceeProgram->contExecution(debug_event->event.signaled.signal);
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
				m_log->error("ERROR : UNKNOWN state {}", debug_event->event.type);
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
			switch (debug_event->event.type) {
			case TraceeEvent::EXITED:
				m_log->info("SYSCALL : EXITED : process {} has exited!", signalled_pid);
				traceeProgram->toStateExited();
				break;
			case TraceeEvent::SIGNALED:
				m_log->critical("SYSCALL : SIGNALLED : process {} terminated by a signal, Possibly in kernel space!!", signalled_pid);
				traceeProgram->toStateExited();
				break;
			case TraceeEvent::STOPPED:

				if(debug_event->reason.status == TrapReason::SYSCALL) {
					m_log->info("SYSCALL EXIT");
					// change the state once we have process the event
					m_syscallMngr->onExit(*traceeProgram);
					traceeProgram->toStateRunning();
				} else if (debug_event->reason.status == TrapReason::CLONE ||
				// this function processes "PTRACE_EVENT stops" event
					debug_event->reason.status == TrapReason::FORK || 
					debug_event->reason.status == TrapReason::VFORK ) {
					// this can happend when you are dealing with fork/vfork/clone
					// system call
					m_log->trace("SYSCALL: CLONE/FORK/VFORK");
					TraceeProgram* tracee_prog = addChildTracee(debug_event->reason.pid);
					if (debug_event->reason.status == TrapReason::CLONE) {
						// attach(debug_event->reason.pid);
						tracee_prog->setThreadGroupid(m_leader_tracee->getPid());
						m_log->trace("New Thead is created with pid {} and tgid {}!", tracee_prog->getPid(), tracee_prog->getThreadGroupid());
					}
					// traceeProgram->contExecution();
				} else if( debug_event->reason.status == TrapReason::EXEC) {
					m_log->trace("SYSCALL: EXEC");
					// traceeProgram->contExecution();
				} else if( debug_event->reason.status == TrapReason::EXIT ) {
					// toStateExited();
					m_log->trace("SYSCALL: EXIT");
					// traceeProgram->contExecution();
				} else {
					m_log->warn("SYSCALL: Not sure why we have stopped!");
					traceeProgram->contExecution(debug_event->event.signaled.signal);
					break;
				}
				traceeProgram->contExecution();
				break;
			default:
				m_log->error("SYSCALL : ERROR : UNKNOWN state {}", debug_event->event.type);
			
		}
			break;
		default:
			m_log->error("FATAL : Undefined Tracee State", debug_event->event.type);
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

