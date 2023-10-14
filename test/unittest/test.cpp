#include <iostream>
#include <cstdint>
#include "debugger.hpp"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include <gtest/gtest.h>
#include "gmock/gmock.h"

using ::testing::AtLeast;
using ::testing::_;


class SyscallOpenatMock : public SyscallHandler {

public:	

	SyscallOpenatMock(): SyscallHandler(NR_openat) {}
    MOCK_METHOD(int, onEnter, (DebugOpts* debug_opts, SyscallTraceData* sc_trace));
    MOCK_METHOD(int, onExit, (DebugOpts* debug_opts, SyscallTraceData* sc_trace));
    ~SyscallOpenatMock() {}
};

class SyscallOpenatAgaingMock : public SyscallHandler {

public:	

	SyscallOpenatAgaingMock(): SyscallHandler(NR_openat) {}
    MOCK_METHOD(int, onEnter, (DebugOpts* debug_opts, SyscallTraceData* sc_trace));
    MOCK_METHOD(int, onExit, (DebugOpts* debug_opts, SyscallTraceData* sc_trace));
    ~SyscallOpenatAgaingMock() {}
};

class FileOptsMock : public FileOperationTracer {

public:

    bool onFilter(DebugOpts* debug_opts, SyscallTraceData *sc_trace) {
		
		// spdlog::warn("onFilter!");

		switch(sc_trace->sc_id) {
		case NR_openat:
			Addr file_path_addr_t(sc_trace->v_arg[1], 100);
			debug_opts->m_memory->read(&file_path_addr_t, 100);
			if (strcmp(reinterpret_cast<char*>(file_path_addr_t.m_data), "/home/hussain/hi.txt") == 0) {
				spdlog::trace("We found the file we wanted to mess with!");
				return true;
			}
			break;
		}
		return false;
	}
    // MOCK_METHOD(bool, onFilter, (DebugOpts* debug_opts, SyscallTraceData *sc_trace));

	MOCK_METHOD(void, onRead, (SyscallState sys_state, DebugOpts* debug_opts, SyscallTraceData *sc_trace));

	MOCK_METHOD(void, onClose, (SyscallState sys_state, DebugOpts* debug_opts, SyscallTraceData *sc_trace));
    
    MOCK_METHOD(void, onWrite, (SyscallState sys_state, DebugOpts* debug_opts, SyscallTraceData *sc_trace));
    
    MOCK_METHOD(void, onIoctl, (SyscallState sys_state, DebugOpts* debug_opts, SyscallTraceData *sc_trace));

};

auto main_logger = spdlog::basic_logger_mt("main_log", "/dev/null");

TEST(FileOptsTest, CallbackAssertions)
{
    Debugger debug;
    
    // mocked object
    FileOptsMock file_opts_mock;

    // EXPECT_CALL(file_opts_mock, onFilter(_, _)).Times(AtLeast(1));
    EXPECT_CALL(file_opts_mock, onRead(_, _, _)).Times(AtLeast(1));
    EXPECT_CALL(file_opts_mock, onWrite(_, _, _)).Times(AtLeast(1));
    EXPECT_CALL(file_opts_mock, onIoctl(_, _, _)).Times(AtLeast(1));
    EXPECT_CALL(file_opts_mock, onClose(_, _, _)).Times(AtLeast(1));

    std::vector<std::string> cmd_param;
    cmd_param.push_back("build/bin/test_prog");
    cmd_param.push_back("5");
    debug.addFileOperationHandler(&file_opts_mock);
    debug.traceSyscall();
    debug.spawn(cmd_param);
    EXPECT_TRUE(debug.eventLoop());
}

TEST(SyscallTest, CallbackAssertions)
{
    Debugger debug;
    
    // mocked object
    SyscallOpenatMock openat_handle;
    SyscallOpenatAgaingMock openat_again_handle;
    
    EXPECT_CALL(openat_handle, onEnter(_, _)).Times(AtLeast(1));
    EXPECT_CALL(openat_handle, onExit(_, _)).Times(AtLeast(1));

    EXPECT_CALL(openat_again_handle, onEnter(_, _)).Times(AtLeast(1));
    EXPECT_CALL(openat_again_handle, onExit(_, _)).Times(AtLeast(1));

    std::vector<std::string> cmd_param;
    cmd_param.push_back("build/bin/test_prog");
    cmd_param.push_back("5");
    debug.addSyscallHandler(&openat_handle);
    debug.addSyscallHandler(&openat_again_handle);
    debug.traceSyscall();
    debug.spawn(cmd_param);
    EXPECT_TRUE(debug.eventLoop());
}

TEST(DebuggerTest, ChildSpawnAssertions)
{
    Debugger debug;
    std::vector<std::string> cmd_param;
    cmd_param.push_back("build/bin/test_prog");
    cmd_param.push_back("5");

    debug.spawn(cmd_param);
    EXPECT_TRUE(debug.eventLoop());
}

// Demonstrate some basic assertions.
TEST(HelloTest, BasicAssertions) {
  // Expect two strings not to be equal.
  EXPECT_STRNE("hello", "world");
  // Expect equality.
  EXPECT_EQ(7 * 6, 42);
}
