#ifndef _H_SYSCALL_COLLECTIONS
#define _H_SYSCALL_COLLECTIONS

#include "utils.hpp"

class DataSocket : public NetworkOperationTracer
{

	bool onFilter(DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("Lets filter some stuff !");
		struct sockaddr_in *sock;
		struct sockaddr *client_sock_addr;
		int new_client_fd = -1;
		Addr socket_data(0, sizeof(struct sockaddr_in));
		Addr client_socket(0, sizeof(struct sockaddr));

		switch (sc_trace.getSyscallNo())
		{
		case SysCallId::SOCKET:
			m_log->warn("New Socket descriptor is created");
			break;
		case SysCallId::BIND:
			m_log->warn("Server : Binding calls");
			socket_data.setRemoteAddress(sc_trace.v_arg[1]);
			debugOpts.m_memory.readRemoteAddrObj(socket_data, sc_trace.v_arg[2]);
			sock = (struct sockaddr_in *)socket_data.data();
			m_log->warn("Socket IP {} port {}", sock->sin_addr.s_addr, ntohs(sock->sin_port));
			return true;
			break;
		case SysCallId::CONNECT:
			m_log->warn("Client : connecting to the server");
			return true;
			break;
		case SysCallId::ACCEPT:
			new_client_fd = sc_trace.v_rval;
			client_socket.setRemoteAddress(sc_trace.v_arg[1]);
			m_log->warn("Sock addr {:x} {}", sc_trace.v_arg[1], sc_trace.v_arg[2]);

			debugOpts.m_memory.readRemoteAddrObj(client_socket, sizeof(struct sockaddr));
			m_log->warn("Server : New Client connection with fd {}", new_client_fd);
			client_sock_addr = (struct sockaddr *)socket_data.data();
			m_log->warn("{}", spdlog::to_hex(
								  std::begin(client_sock_addr->sa_data),
								  std::begin(client_sock_addr->sa_data) + 14));
			return true;
			break;
		case SysCallId::LISTEN:
			m_log->warn("Server : Started listening...");
			break;
		default:
			break;
		}

		return false;
	}

	void onRecv(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &sc_trace)
	{
		char malicious_text[] = "This is malicious data which is been intercepted and fille with!";
		if (sys_state == SyscallState::ON_EXIT)
		{
			int fd = static_cast<int>(sc_trace.v_arg[0]);
			uint64_t buf_ptr = sc_trace.v_arg[1];
			uint64_t buf_len = sc_trace.v_arg[2];
			uint64_t actual_read = sc_trace.v_rval;

			m_log->debug("onRead: {:x} {} -> {}", buf_ptr, buf_len, actual_read);
			Addr buf(buf_ptr, buf_len);
			debug_opts.m_memory.readRemoteAddrObj(buf, buf_len);
			buf.print();
			buf.copy_buffer((uint8_t *)malicious_text, buf_len);
			debug_opts.m_memory.writeRemoteAddrObj(buf, buf_len);
		}
	}

	void onSend(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &sc_trace)
	{
		char malicious_text[] = "This is malicious data which is been intercepted and fille with!";
		if (sys_state == SyscallState::ON_ENTER)
		{
			int fd = static_cast<int>(sc_trace.v_arg[0]);
			uint64_t buf_ptr = sc_trace.v_arg[1];
			uint64_t buf_len = sc_trace.v_arg[2];
			uint64_t actual_write = sc_trace.v_rval;

			m_log->debug("onWrite: {:x} {} -> {}", buf_ptr, buf_len, actual_write);
			Addr *buf = debug_opts.m_memory.readPointerObj(buf_ptr, buf_len);
			buf->print();
			memcpy(buf->data(), malicious_text, buf_len);
			debug_opts.m_memory.writeRemoteAddrObj(*buf, buf_len);
		}
	}
};

struct OverwriteFileData : public FileOperationTracer
{

	bool onFilter(DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("onFilter!");

		switch (sc_trace.getSyscallNo())
		{
		case SysCallId::OPENAT:
			Addr file_path_addr_t(sc_trace.v_arg[1], 100);
			debugOpts.m_memory.readRemoteAddrObj(file_path_addr_t, 100);
			m_log->trace("File path : {}", (char *)file_path_addr_t.data());
			if (strcmp(reinterpret_cast<char *>(file_path_addr_t.data()), "/home/hussain/hi.txt") == 0)
			{
				m_log->trace("We found the file we wanted to mess with!");
				return true;
			}
			break;
		}
		return false;
	}

	void onRead(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &sc_trace)
	{
		if (sys_state == SyscallState::ON_ENTER)
		{
			m_log->debug("onRead: onEnter");
			int fd = static_cast<int>(sc_trace.v_arg[0]);
			uint64_t buf_len = sc_trace.v_arg[2];
			Addr buf(sc_trace.v_arg[1], buf_len);
			m_log->warn("FD {} ptr 0x{:x} len 0x{:x}", fd, buf.raddr(), buf_len);
		}
		else
		{
			m_log->warn("onRead: onExit");
			int fd = static_cast<int>(sc_trace.v_arg[0]);
			uint64_t buf_len = sc_trace.v_arg[2];
			Addr buf(sc_trace.v_arg[1], buf_len);
			debug_opts.m_memory.readRemoteAddrObj(buf, buf_len);
			m_log->critical("Read : {}", reinterpret_cast<char *>(buf.data()));
			// m_log->warn("{} {} {}", fd, reinterpret_cast<char *>(buf.data()), buf_len);
			// const char * mal_cont = "Malicious\x00";
			// memcpy(buf.data(), mal_cont, sizeof(mal_cont));
			const uint8_t mal_data[16] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
										  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
			buf.copy_buffer(mal_data, sizeof(mal_data));
			debug_opts.m_memory.writeRemoteAddrObj(buf, sizeof(mal_data));
		}
	}

	// void onClose(SyscallState sys_state, DebugOpts& debug_opts, SyscallTraceData& sc_trace) {
	// 	m_log->trace("onClose");
	// }
};

void print_hex(uint8_t *buf, size_t buf_size)
{
    for (int i = 0; i < buf_size; i++)
    {
        printf("%02X ", buf[i], i + 1);
        if ((i + 1) % 32 == 0)
        {
            printf("\n");
        }
    }

}
struct RandomeFileData : public FileOperationTracer
{
    Rand m_rand;

    RandomeFileData(uint64_t seed) : m_rand(Rand(seed)) { }

	/// @brief This filter function does some very simple, if the 
	///        file been open is "/dev/randomCheck" return true else false
	/// @param debugOpts 
	/// @param sc_trace 
	/// @return 
	bool onFilter(DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("onFilter!");

		switch (sc_trace.getSyscallNo())
		{
		case SysCallId::OPENAT:

			Addr file_path_addr_t(sc_trace.v_arg[1], 100);
			debugOpts.m_memory.readRemoteAddrObj(file_path_addr_t, 100);
			m_log->trace("File path : {}", (char *)file_path_addr_t.data());
			if (strcmp(reinterpret_cast<char *>(file_path_addr_t.data()), "/dev/random") == 0)
			{
				m_log->error("We found the file we wanted to mess with!");
				return true;
			}
			break;
		}
		return false;
	}

	void onRead(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &sc_trace)
	{
        if (sys_state == SyscallState::ON_ENTER)
		{
			m_log->debug("onRead: onEnter");
			int fd = static_cast<int>(sc_trace.v_arg[0]);
            uintptr_t buf_addr = sc_trace.v_arg[1];
			uint64_t buf_len = sc_trace.v_arg[2];
			Addr fd_read_buf(buf_addr, buf_len);
			debug_opts.m_memory.readRemoteAddrObj(fd_read_buf, buf_len);
            fd_read_buf.print();
		}
		if (sys_state == SyscallState::ON_EXIT)
		{
			m_log->warn("onRead: onExit");
			int fd = static_cast<int>(sc_trace.v_arg[0]);
            uintptr_t buf_addr = sc_trace.v_arg[1];
			uint64_t buf_len = sc_trace.v_arg[2];
			Addr fd_read_buf(buf_addr, buf_len);
			debug_opts.m_memory.readRemoteAddrObj(fd_read_buf, buf_len);
            fd_read_buf.print();
			m_log->critical("Read with buf_len {}", buf_len);
            m_rand.fillBuffer(fd_read_buf.data(), buf_len);
            fd_read_buf.print();
			debug_opts.m_memory.writeRemoteAddrObj(fd_read_buf, buf_len);
		}
	}
};

class OpenAt1Handler : public SyscallHandler
{

public:
	OpenAt1Handler() : SyscallHandler(SysCallId::OPEN) {}

	int onEnter(SyscallTraceData &sc_trace)
	{
		m_log->debug("onEnter : System call handler test");
		m_log->debug("openat({:x}, {:x}, {}, {}) [{}]", sc_trace.v_arg[0], sc_trace.v_arg[1], sc_trace.v_arg[2], sc_trace.v_arg[3], sc_trace.v_rval);
		return 0;
	}
	int onExit(SyscallTraceData &sc_trace)
	{
		m_log->debug("onExit : System call handler test");
		m_log->debug("openat({:x}, {:x}, {}, {}) [{}]", sc_trace.v_arg[0], sc_trace.v_arg[1], sc_trace.v_arg[2], sc_trace.v_arg[3], sc_trace.v_rval);
		return 0;
	}
};

class OpenAt2Handler : public SyscallHandler
{

public:
	OpenAt2Handler() : SyscallHandler(SysCallId::OPENAT) {}

	int onEnter(SyscallTraceData &sc_trace)
	{
		m_log->debug("onEnter : System call handler test again!");
		m_log->debug("openat({:x}, {:x}, {}, {}) [{}]", sc_trace.v_arg[0], sc_trace.v_arg[1], sc_trace.v_arg[2], sc_trace.v_arg[3], sc_trace.v_rval);
		return 0;
	}

	int onExit(SyscallTraceData &sc_trace)
	{
		m_log->debug("onExit : System call handler test again!");
		m_log->debug("openat({:x}, {:x}, {}, {}) [{}]", sc_trace.v_arg[0], sc_trace.v_arg[1], sc_trace.v_arg[2], sc_trace.v_arg[3], sc_trace.v_rval);
		return 0;
	}
};

#endif