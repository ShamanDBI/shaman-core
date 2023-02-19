#ifndef H_DEBUGGER_H
#define H_DEBUGGER_H

#include <map>
#include <spdlog/spdlog.h>

#include "tracee.hpp"
#include "linux_debugger.hpp"


class TraceeProgram;


class Debugger {

	std::map<pid_t, TraceeProgram*> m_Tracees;
	std::string* m_prog = nullptr;
	std::vector<std::string>* m_argv = nullptr;
	std::vector<std::string>& brk_pnt_str;

public:

	Debugger(std::vector<std::string>& _brk_pnt_str):
		brk_pnt_str(_brk_pnt_str) {}

	int spawn(std::vector<std::string>& cmdline);

	void addChildTracee(pid_t child_tracee_pid);

	void dropChildTracee(TraceeProgram* child_tracee);

	void printAllTraceesInfo();

	TrapReason getTrapReason(TraceeEvent event, TraceeProgram* tracee_info);

	void eventLoop();

	bool isBreakpointTrap(siginfo_t* tracee_pid);
	
	void parseBrk(std::vector<std::string>& brk_pnt_str);
};

#endif
