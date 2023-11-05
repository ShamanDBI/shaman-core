#include <sys/wait.h>
#include <spdlog/spdlog.h>


#include "linux_debugger.hpp"


void TraceeEvent::print() {
	spdlog::debug("[{}] TraceeStatus", pid);
	switch (type) {
		case TraceeEvent::EXITED :
			spdlog::debug("EXITED : {}",exited.status);
			break;
		case TraceeEvent::SIGNALED:
			spdlog::debug("SIGNALED : {}",signaled.signal);
			break;
		case TraceeEvent::STOPPED:
			spdlog::debug("STOPPED : signal {} {}",stopped.signal, stopped.status);
			break;
		case TraceeEvent::CONTINUED:
			spdlog::debug("CONTINUED");
			break;
		case TraceeEvent::INVALID:
			spdlog::debug("INVALID");
			break;
		default:
			spdlog::debug("Don't Know");
			break;
	}

}

TraceeEvent::~TraceeEvent() {
	// spdlog::debug("~TraceeEvent : out of scope");
	type = TraceeEvent::INVALID;
	pid = 0;
}

TraceeEvent get_wait_event(pid_t pid) {
	TraceeEvent t_status;
    int child_status;
    int wait_ret = waitpid(pid, &child_status, WNOHANG | WCONTINUED);
    if (wait_ret == -1) {
        spdlog::error("waitpid failed !");
    }
	t_status.type = TraceeEvent::INVALID;
	if (wait_ret == 0) {
		// this is no event for the child, exit no futher detail needed
		return t_status;
	}
	if (WIFSIGNALED(child_status)) {
		// cout << "WIFSIGNALED" << endl;
		t_status.type = TraceeEvent::SIGNALED;
		t_status.signaled.signal = WTERMSIG(child_status);
		t_status.signaled.dumped =  WCOREDUMP(child_status);
	} else if (WIFEXITED(child_status)) {
		// cout << "WIFEXITED" << endl;
		t_status.type = TraceeEvent::EXITED;
		t_status.exited.status = WEXITSTATUS(child_status);
	} else if (WIFSTOPPED(child_status)) {
		// cout << "WIFSTOPPED" << endl;
		t_status.type = TraceeEvent::STOPPED;
		t_status.stopped.signal = WSTOPSIG(child_status);
		t_status.stopped.status = child_status;
	} else if (WIFCONTINUED(child_status)) {
		// cout << "WIFCONTINUED" << endl;
		t_status.type = TraceeEvent::CONTINUED;
	} else {
		spdlog::error("Unreachable Tracee state please handle it!");
		exit(-1);
	}
	return t_status;
}

void TrapReason::print() {
	spdlog::debug("[{}] TrapReason", pid);
	switch (status) {
		case TrapReason::EXEC :
			spdlog::debug("EXITED");
			break;
		case TrapReason::FORK:
			spdlog::debug("FORK");
			break;
		case TrapReason::BREAKPOINT:
			spdlog::debug("BREAKPOINT");
			break;
		case TrapReason::SYSCALL:
			spdlog::debug("SYSCALL");
			break;
		case TrapReason::INVALID:
			spdlog::debug("INVALID");
			break;
	}
}

TrapReason::~TrapReason() {
	// spdlog::debug("~TrapReason : out of scope");
	status = INVALID;
	pid = 0;
}