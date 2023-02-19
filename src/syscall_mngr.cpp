// Taken from : https://gist.github.com/SBell6hf/77393dac37939a467caf8b241dc1676b

#define CASE_SYSCALL(id, name) case id: spdlog::trace("syscall {} - {}", id, name); break;


void printSyscall(pid_t tracee_pid) {
	struct iovec io;
	struct user_regs_struct regs;
	io.iov_base = &regs;
	io.iov_len = sizeof(struct user_regs_struct);

	if (ptrace(PTRACE_GETREGSET, tracee_pid, (void*)NT_PRSTATUS, (void*)&io) == -1) {
		spdlog::error("Failed to get tracee register");
	}

	auto rem_mem = RemoteMemory(tracee_pid);
	// auto rem_file_path = new Addr(regs.rsi, 100);

	uint32_t syscall_id = regs.orig_rax;
	
	// Ref : https://filippo.io/linux-syscall-table/
	switch (syscall_id) {
		CASE_SYSCALL(0, "read")
		// case 257: {
		// 	cout << "openat : " ;
		// 	printf("RAX : %p\n", regs.rax);
		// 	printf("RSI : %p\n", regs.rsi);
		// 	printf("RDI : %p\n", regs.rdi);
		// 	printf("RDX : %p\n", regs.rdx);
		// 	printf("RCX : %p\n", regs.rcx);
		// 	printf("R8 : %p\n", regs.r8);
		// 	printf("R9 : %p\n", regs.r9);
		// 	auto rem_file_path = new Addr(regs.rsi, 100);
		// 	getchar();
		// 	rem_mem.read(rem_file_path, 100);
		// 	printf("path - %s \n", rem_file_path->addr);
		// 	delete rem_file_path;
		// 	getchar();
		// }
		CASE_SYSCALL(1, "write")
		CASE_SYSCALL(2, "open")
		CASE_SYSCALL(3, "close")
		CASE_SYSCALL(5, "fstat")
		CASE_SYSCALL(21, "access")
		CASE_SYSCALL(9, "mmap")
		CASE_SYSCALL(10, "mprotect")
		CASE_SYSCALL(11, "munmap")
		CASE_SYSCALL(12, "brk")
		CASE_SYSCALL(56, "clone")
		CASE_SYSCALL(57, "fork")
		CASE_SYSCALL(58, "vfork")
		CASE_SYSCALL(60, "exit")
		CASE_SYSCALL(231, "exit_group")
		// CASE_SYSCALL(257, "openat")
		default:
			cout << "Unknown " << endl;
			break;
	}
}