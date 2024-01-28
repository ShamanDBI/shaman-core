#ifndef H_LINUX_DEBUGGER
#define H_LINUX_DEBUGGER

#include <sys/wait.h>
#include <spdlog/spdlog.h>
#include <tuple>
#include <utility>


#define PT_IF_CLONE(status)   ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)))
#define PT_IF_FORK(status)    ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK  << 8)))
#define PT_IF_VFORK(status)   ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)))
#define PT_IF_EXEC(status)    ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC  << 8)))
#define PT_IF_EXIT(status)    ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT  << 8)))
#define PT_IF_SYSCALL(signal) (signal == (SIGTRAP | 0x80))


struct TraceeEvent {
	
	enum EventType {
		EXITED = 1, SIGNALED, STOPPED, CONTINUED, INVALID
	} type;

	union {
		struct  {
			uint32_t status;
		} exited;

		struct  {
			uint32_t signal;
			bool dumped;
		} signaled;
		
		struct  {
			uint32_t signal;
			uint32_t status;
		} stopped;
	};

	TraceeEvent(EventType et): type(et) {}

	TraceeEvent(TraceeEvent &eventObj):TraceeEvent() {
		type = eventObj.type;

		switch (type)
		{
		case EventType::SIGNALED:
			signaled = eventObj.signaled;
			break;
		case EventType::EXITED:
			exited = eventObj.exited;
			break;
		case EventType::STOPPED:
			stopped.signal = eventObj.stopped.signal;
			stopped.status = eventObj.stopped.status;
		default:
			break;
		}
	}

	TraceeEvent(const TraceeEvent &eventObj) {
		type = eventObj.type;
		spdlog::debug("copy onst TraceeEvent");
		switch (type)
		{
		case EventType::SIGNALED:
			signaled = eventObj.signaled;
			break;
		case EventType::EXITED:
			exited = eventObj.exited;
			break;
		case EventType::STOPPED:
			stopped.signal = eventObj.stopped.signal;
			stopped.status = eventObj.stopped.status;
		default:
			break;
		}
	}

	TraceeEvent& operator=(const TraceeEvent& eventObj) {
		// spdlog::debug("assing value to TraceeEvent");
		type = eventObj.type;
		switch (type)
		{
		case EventType::SIGNALED:
			signaled = eventObj.signaled;
			break;
		case EventType::EXITED:
			exited = eventObj.exited;
			break;
		case EventType::STOPPED:
			stopped.signal = eventObj.stopped.signal;
			stopped.status = eventObj.stopped.status;
		default:
			break;
		}
		return *this;
	}

	void makeInvalid() {
		type = INVALID;
	}

	TraceeEvent(): type(INVALID) {}
	
	~TraceeEvent();
	
	bool isValidEvent() {
		return type != INVALID;
	}

	void setInvalid() {
		type = INVALID;
	}

	void print();
};


struct TrapReason {

	enum {
		CLONE = 1, 	// Process invoked `clone()`
		EXEC, 		// Process invoked `execve()`
		EXIT, 		// Process invoked `exit()`
		FORK, 		// Process invoked `fork()`
		VFORK, 		// Process invoked `vfork()`
		SYSCALL,
		BREAKPOINT,
		ERROR,
		INVALID
	} status;

	pid_t pid; // this holds value of new pid in case of clone/vfork/frok
	
	void print();
	
	~TrapReason();

};


struct DebugEvent {
	// pid of the process causing this event
	pid_t m_pid = 0;
	TraceeEvent event;
	TrapReason reason;

	DebugEvent() {
		event.type = TraceeEvent::INVALID;
		reason.status = TrapReason::INVALID;
	};

	~DebugEvent() {
		event.type = TraceeEvent::INVALID;
		reason.status = TrapReason::INVALID;
	};

	void makeInvalid() {
		event.type = TraceeEvent::INVALID;
		reason.status = TrapReason::INVALID;
	};

	void print() {
		event.print();
		reason.print();
	}

};

typedef std::unique_ptr<DebugEvent> DebugEventPtr;


int get_wait_event(pid_t pid, DebugEventPtr& debug_event);

#endif