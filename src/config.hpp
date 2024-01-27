#ifndef _SYS_COFNIG_H
#define _SYS_COFNIG_H


#define SHAMAN_LOG_LEVEL_TRACE 0
#define SHAMAN_LOG_LEVEL_DEBUG 1
#define SHAMAN_LOG_LEVEL_INFO 2
#define SHAMAN_LOG_LEVEL_WARN 3
#define SHAMAN_LOG_LEVEL_ERROR 4
#define SHAMAN_LOG_LEVEL_CRITICAL 5
#define SHAMAN_LOG_LEVEL_OFF 6


// #define SUPPORT_ARCH_ARM
#define SUPPORT_ARCH_AMD64

// #define SUPPORT_ARCH_ARM64

#define SPDLOG_ACTIVE_LEVEL SHAMAN_LOG_LEVEL_TRACE

// #define SUPPORT_MEM_FILE 1

/**
 * @defgroup programming_interface Programming Interfaces
 * Components which can be pluged into the system which will help you to manipulate the Tracee
 * 
 * The functionality can be broadly classifed into two Inteface, One is System Call and Breakpoint
 * 1. *Breakpoint* will give you abilility to stop and inspect at arbitrary point in the process
 * 2. *SyscallTraceData* will give you ability to stop and inspect before and after the System Call is make 
 * 
 * @defgroup platform_support Platform Support
 * To add support for new Architecture you need to implement different 
 * interfaces for Architecture specific impelementation
 */

#endif