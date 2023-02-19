#include "debugger.hpp"
#include "memory.hpp"
#include "modules.hpp"


using namespace std;


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
	spdlog::info("Spawning process {}", m_prog->c_str());
	pid_t childPid = fork();
	
	if (childPid == -1) {
		spdlog::error("fork() for tracee failed failed!");
		return -1;
	}

	if (childPid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, 0, 0)) {
			return -1;
		}
		
		int status_code = execvp(args[0], const_cast<char* const *>(args.data()));

		if (status_code == -1) {
			spdlog::error("Process did not terminate correctly\n");
			exit(1);
		}

		spdlog::debug("This line will not be printed if execvp() runs correctly\n");

		return 0;
	}

	spdlog::debug("New Child spawed with PID {}", childPid);
	
	addChildTracee(childPid);
	return 0;
}

void Debugger::addChildTracee(pid_t child_tracee_pid) {
	if (child_tracee_pid == 0) {
		spdlog::critical("FATAL : Whhaat tthhhee.... heelll...., child id cannot be zero! Not adding child to the list");
	} else {
		spdlog::debug("New child {} is added to trace list!", child_tracee_pid);
		auto tracee_obj = new TraceeProgram(child_tracee_pid, *this);
		tracee_obj->addPendingBrkPnt(brk_pnt_str);
		m_Tracees.insert(make_pair(child_tracee_pid, tracee_obj));
	}
}

void Debugger::dropChildTracee(TraceeProgram* child_tracee) {
	spdlog::debug("Dropping child tracee PID : {}", child_tracee->m_pid);
	m_Tracees.erase(child_tracee->m_pid);
	delete child_tracee;
}

void Debugger::printAllTraceesInfo() {
	spdlog::debug("Tracee state : ");
	TraceeProgram *tc_info = nullptr;
	for (auto i = m_Tracees.begin(); i != m_Tracees.end(); i++) {
		// spdlog::debug("ID : {}", i->first);
		tc_info = i->second;
		tc_info->printStatus();
	}
}

bool Debugger::isBreakpointTrap(siginfo_t* info) {
	spdlog::debug("BK test signal code : {}", info->si_code);

	switch (info->si_code) {
	//one of these will be set if a breakpoint was hit
	case SI_KERNEL:
		spdlog::trace("Breakpoint TRAP : KERNEL");
	case TRAP_BRKPT:
		spdlog::trace("Breakpoint TRAP : Software");
		return true;
	case TRAP_TRACE:
		//this will be set if the signal was sent by single stepping
		spdlog::trace("Breakpoint : TRAP_TRACE, possibly due to single stepping!");
		return true;
	default:
		spdlog::error("Unknown SIGTRAP code {}", info->si_code);
	}
	return false;
}

TrapReason Debugger::getTrapReason(TraceeEvent event, TraceeProgram* tracee_info) {
	pid_t new_pid = -1;
	pid_t pid_sig = tracee_info->m_pid;

	TrapReason trap_reason = { TrapReason::INVALID, -1 };

	if(event.type == TraceeEvent::STOPPED && event.stopped.signal == SIGTRAP) {
		if (PT_IF_CLONE(event.stopped.status)) {
			spdlog::trace("SIGTRAP : CLONE");
			new_pid = 0;
			int pt_ret = ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
			// spdlog::trace("SIGTRAP : PT CLONE : ret {}");
			trap_reason.status = TrapReason::CLONE;
			trap_reason.pid = new_pid;
		} else if (PT_IF_EXEC(event.stopped.status)) {
			spdlog::trace("SIGTRAP : Exec");
			trap_reason.status = TrapReason::EXEC;
			trap_reason.pid = -1;
		} else if (PT_IF_EXIT(event.stopped.status)) {
			spdlog::trace("SIGTRAP : Exit");
			trap_reason.status = TrapReason::EXIT;
			trap_reason.pid = -1;
		} else if (PT_IF_FORK(event.stopped.status)) {
			spdlog::trace("SIGTRAP : Fork");
			new_pid = 0;
			int pt_ret = ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
			trap_reason.status = TrapReason::FORK;
			trap_reason.pid = new_pid;
		} else if (PT_IF_VFORK(event.stopped.status)) {
			spdlog::trace("SIGTRAP : VFork");
			new_pid = 0;
			// Get the PID of the new process
			int pt_ret = ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
			trap_reason.status = TrapReason::VFORK;
			trap_reason.pid = new_pid;
		} else {
			if(!tracee_info->isInitialized()) {
				siginfo_t sig_info;
				ptrace(PTRACE_GETSIGINFO, pid_sig, nullptr, &sig_info);
				if (isBreakpointTrap(&sig_info)) {
					spdlog::trace("SIGTRAP : Breakpoint was hit !");
					trap_reason.status = TrapReason::BREAKPOINT;
				} else {
					spdlog::warn("SIGTRAP : Couldn't Find Why are we trapped! Need to handle this!");
				}
			}
		}
	} else if (event.type == TraceeEvent::STOPPED && PT_IF_SYSCALL(event.stopped.signal)) {
		spdlog::trace("SIGTRAP : SYSCALL");
		trap_reason.status = TrapReason::SYSCALL;
	} else if (event.type == TraceeEvent::STOPPED) {
		spdlog::warn("This STOP Signal not understood by us!");
	}
	return trap_reason;
}

void Debugger::eventLoop() {
		
	siginfo_t pt_sig_info = {0};
	TraceeEvent event;
	TraceeProgram *traceeProg;
	TraceeEvent invalid_event = TraceeEvent();

	while(!m_Tracees.empty()) {
		spdlog::debug("------------------------------");
		pt_sig_info.si_pid = 0;	
		traceeProg = nullptr;
		event = invalid_event;

		printAllTraceesInfo();

		int ret_wait = waitid(
			P_ALL, 0, 
			&pt_sig_info,
			WEXITED | WSTOPPED | WCONTINUED | WNOWAIT
		);

		if (ret_wait == -1) {
			spdlog::critical("waitid failed!");
			exit(-1);
		}
		
		pid_t pid_sig = pt_sig_info.si_pid;
		if (pid_sig == 0) {
			spdlog::warn("Special Case of waitid(), please handle it!");
			exit(-1);
		}

		spdlog::info("Signaled Pid : {} Signal Code : {}", pid_sig, pt_sig_info.si_code);

		auto tracee_iter = m_Tracees.find(pid_sig);
		if (tracee_iter != m_Tracees.end()) {
			// tracee is found, its under over management
			traceeProg = tracee_iter->second;
		} else {
			spdlog::info("Tracee not found!");
			traceeProg = nullptr;
		}
		
		if (traceeProg == nullptr) {
			spdlog::info("Tracee is not under over management");
			// reset the current processed tracee info
			event = invalid_event;
			pid_sig = -1;
			bool found_event = false;
			for (auto i = m_Tracees.begin(); i != m_Tracees.end(); i++) {
				pid_t tracee_pid = i->first;
				TraceeEvent ts_event = get_wait_event(tracee_pid);
				traceeProg = i->second;
				spdlog::debug("Inspecting ");
				traceeProg->printStatus();
				ts_event.print();
				if (ts_event.isValidEvent()) {
					found_event = true;
					spdlog::debug("Event from PID : {}", tracee_pid);
					pid_sig = tracee_pid;
					traceeProg = m_Tracees[pid_sig];
					event = ts_event;
					break;
				}
			}
			if(!found_event) {
				spdlog::critical("No tracee with event found! This should not happend, handle it!");
			}
		} else {
			event = get_wait_event(pid_sig);
		}

		if (traceeProg) {
			TrapReason trap_reason = getTrapReason(event, traceeProg);
			traceeProg->processState(event, trap_reason);
			if (traceeProg->hasExited()) {
				traceeProg->m_breakpointMngr.printStats();
				dropChildTracee(traceeProg);				
			}
		}
		// processTraceeState(tracee_info, trap_reason);
	}
	spdlog::info("There are not tracee left to debug. Exiting!");
}
