#include "breakpoint.hpp"
#include "debug_opts.hpp"


// ------------------------------- ARM ISA ------------------------------------

/* Under ARM GNU/Linux the traditional way of performing a breakpoint
   is to execute a particular software interrupt, rather than use a
   particular undefined instruction to provoke a trap. Upon exection
   of the software interrupt the kernel stops the inferior with a
   SIGTRAP, and wakes the debugger.  */

static const uint8_t arm_linux_arm_le_breakpoint[] = { 0x01, 0x00, 0x9f, 0xef };

static const uint8_t arm_linux_arm_be_breakpoint[] = { 0xef, 0x9f, 0x00, 0x01 };

/* However, the EABI syscall interface (new in Nov. 2005) does not look at
   the operand of the swi if old-ABI compatibility is disabled.  Therefore,
   use an undefined instruction instead.  This is supported as of kernel
   version 2.5.70 (May 2003), so should be a safe assumption for EABI
   binaries.  */

static const uint8_t eabi_linux_arm_le_breakpoint[] = { 0xf0, 0x01, 0xf0, 0xe7 };

static const uint8_t eabi_linux_arm_be_breakpoint[] = { 0xe7, 0xf0, 0x01, 0xf0 };

/* All the kernels which support Thumb support using a specific undefined
   instruction for the Thumb breakpoint.  */

static const uint8_t arm_linux_thumb_be_breakpoint[] = {0xde, 0x01};

static const uint8_t arm_linux_thumb_le_breakpoint[] = {0x01, 0xde};

/* Because the 16-bit Thumb breakpoint is affected by Thumb-2 IT blocks,
   we must use a length-appropriate breakpoint for 32-bit Thumb
   instructions.  See also thumb_get_next_pc.  */

static const uint8_t arm_linux_thumb2_be_breakpoint[] = { 0xf7, 0xf0, 0xa0, 0x00 };

static const uint8_t arm_linux_thumb2_le_breakpoint[] = { 0xf0, 0xf7, 0x00, 0xa0 };


void ARMBreakpointInjector::inject(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData) {
    // TODO : save the data of the breakpoint location in the buffer this
    // should have you a system call in the next breakpoint handling
    m_log->debug("Injection breakpoint 0x{:x}!", m_backupData->raddr());
    // 
    size_t brk_pnt_size = 4;
    bool thumb_mode = false;
    if (m_backupData->raddr() & 1) {
        thumb_mode = true;
        brk_pnt_size = 2;
    }
    // Create shadow copy of the original instrucation
    const uint8_t* tmp_backup_byte = (uint8_t*) malloc(brk_pnt_size);
    debug_opts.m_memory.readRemoteAddrObj(*m_backupData.get(), brk_pnt_size);
    
    m_backupData->print();
    // storing it in the temperory variable
    memcpy((void *)tmp_backup_byte, m_backupData->data(), brk_pnt_size);

    
    // if(tmp_backup_byte == BREAKPOINT_X86_INST) {
        // m_log->critical("pid {} Breakpoint is already in place! {:x}",
        //     debug_opts.getPid(), m_backupData->raddr());
    // }
    // m_log->critical("pid {} {:x}", debug_opts.getPid(), m_backupData->raddr());
    
    // Write the breakpoint instruction into shadow copy 
    if (thumb_mode) {
        m_backupData->copy_buffer(arm_linux_thumb_le_breakpoint, brk_pnt_size);
    } else {
        int is_equal = memcmp(eabi_linux_arm_le_breakpoint, tmp_backup_byte, sizeof(eabi_linux_arm_le_breakpoint));
        if(is_equal == 0) {
            m_log->error("The breakpoint is already placed at 0x{:x}", m_backupData->raddr());
            getchar();
        }
        m_backupData->copy_buffer(eabi_linux_arm_le_breakpoint, brk_pnt_size);
    }

    m_backupData->print();
    // Shadow copy is commit to the process memory
    // m_log->warn("All this point {}", brk_pnt_size);
    debug_opts.m_memory.writeRemoteAddrObj(*m_backupData.get(), 4);
    // debug_opts.m_memory.write(m_backupData, 8);
    // Restore the shadow copy with the original instruction
    m_backupData->copy_buffer(tmp_backup_byte, brk_pnt_size);
    free((void *)tmp_backup_byte);
    m_log->debug("Injection Done 0x{:x}!", m_backupData->raddr());
}

void ARMBreakpointInjector::restore(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData) {

    size_t brk_pnt_size = 4;
    bool thumb_mode = false;
    
    if (m_backupData->raddr() & 1) {
        thumb_mode = true;
        brk_pnt_size = 2;
    }
    m_log->debug("Restoring breakpoint 0x{:x}!", m_backupData->raddr());
    m_backupData->print();
    debug_opts.m_memory.writeRemoteAddrObj(*m_backupData.get(), brk_pnt_size);
    // m_backupData->print();
}