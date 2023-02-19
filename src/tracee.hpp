#ifndef H_TRACEE_H
#define H_TRACEE_H

#include "memory.hpp"
#include "debugger.hpp"
#include "modules.hpp"
#include "breakpoint_mngr.hpp"
#include "linux_debugger.hpp"
#include "registers.hpp"


enum DebugType {
	DEFAULT        = (1 << 1),
	BREAKPOINT     = (1 << 2),
	FOLLOW_FORK    = (1 << 3),
	SYSCALL        = (1 << 4),
	SINGLE_STEP    = (1 << 5)
};

class Debugger;

class TraceeProgram {

	// this is current state of the tracee
	enum TraceeState {
		// once the tracee is spawned it is assigned this state
		// tracee is then started with the desired ptrace options
		INITIAL_STOP = 1,
		// on the initialization is done it is set in the running
		// state
		RUNNING,
		// tracee is put in this state when it has sent request to
		// kernel and the kernel is processing system call, this 
		// mean syscall enter has already occured
		SYSCALL,
		// the process has existed and object is avaliable to free
		EXITED, 
		UNKNOWN
	} m_state ;

	DebugType debugType;	
	Debugger& m_debugger;
	RemoteMemory* m_TraceeMemory;
	ProcessMap* m_procMap;
	Registers m_register;

public:

	BreakpointMngr m_breakpointMngr;
	pid_t m_pid; // tracee pid
	// TraceeEvent event; // this represnt current event of event loop
	
	~TraceeProgram () {
		delete m_TraceeMemory;
		delete m_procMap;
	}

	// this is used when new tracee is found
	TraceeProgram(pid_t tracee_pid, Debugger& debugger, DebugType debug_type):
		m_state(TraceeState::INITIAL_STOP), m_debugger(debugger),
		m_pid(tracee_pid), debugType(debug_type), 
	 	m_TraceeMemory(new RemoteMemory(tracee_pid)),
		m_procMap(new ProcessMap(tracee_pid)),
		m_register(Registers(tracee_pid)),
		m_breakpointMngr(BreakpointMngr(tracee_pid, m_procMap)) {}
	
	TraceeProgram(pid_t tracee_pid, Debugger& debugger):
		TraceeProgram(tracee_pid, debugger, DebugType::DEFAULT) {}


	bool isValidState();

	DebugType getChildDebugType();

	bool isInitialized();

	void toStateRunning();

	void toStateSysCall();

	void toStateExited();

	bool hasExited();

	int contExecution(uint32_t sig = 0);

	int singleStep();

	std::string getStateString();

	void printStatus();

	void processPtraceEvent(TraceeEvent event, TrapReason trap_reason);

	void processINITState();

	void processRUNState(TraceeEvent event, TrapReason trap_reason);

	void processSYSCALLState(TraceeEvent event, TrapReason trap_reason);

	void processState(TraceeEvent event, TrapReason trap_reason);

	void addPendingBrkPnt(std::vector<std::string>& brk_pnt_str);

};

#endif