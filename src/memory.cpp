// #include "memory.hpp"
#include <cstdint>
#include <cstdlib>
#include <sys/ptrace.h>
#include <cstring>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sstream>
#include <elf.h>
#include <spdlog/spdlog.h>
#include <map>
#include "stdio.h"
#include "modules.hpp"

using namespace std;

class Addr {

private:

public:
    uint8_t* addr;
    uint64_t r_addr;
    size_t size;
    
    // memory size should be the multiple of memory pointer size
    // so for 64-bit system it should be multiple of 8 and for
    // 32-bit system it should be multiple of 4
    Addr(uint64_t _r_addr, size_t _size): size(_size), r_addr(_r_addr) {
        addr = (uint8_t *) malloc(_size);
        // printf("mem alloc , %lu\n", size);
    }
    void clean() {
        // set the data to zero
        memset(addr, 0, size);
    }

    ~Addr() {
        // if(addrType == LOCAL)
            free(addr);
    }
};


#define ARCH_GP_REG_CNT 27

enum INTEL_X64_REGS {
    R15 = 0,
    R14,
    R13,
    R12,
    RBP,
    RBX,
    R11,
    R10,
    R9,
    R8,
    RAX,
    RCX,
    RDX,
    RSI,
    RDI,
    ORIG_RAX,
    RIP,
    CS,
    EFLAGS,
    RSP,
    SS,
    FS_BASE,
    GS_BASE,
    DS,
    ES,
    FS,
    GS,
};

struct UserRegs {
    uint64_t reg[ARCH_GP_REG_CNT];
    uint64_t pc;
    uint64_t sp;

    uint64_t getPC() {
        return reg[INTEL_X64_REGS::RIP];
    }

    uint64_t setPC(uint64_t reg_val) {
        return reg[INTEL_X64_REGS::RIP] = reg_val;
    }

    uint64_t getSP() {
        return reg[INTEL_X64_REGS::RSP];
    }

    static UserRegs * createGP(void* regs, size_t reg_size) {
        auto gp_regs = new UserRegs;
        memcpy(gp_regs->reg, regs, reg_size);
        return gp_regs;
    }

    void print() {
        spdlog::debug("---------------------------------[ REGISTERS START]--------------------------------");
        spdlog::debug("RAX {:16x} RBX {:16x} RCX {:16x} RDX {:16x}", 
            reg[INTEL_X64_REGS::RAX], reg[INTEL_X64_REGS::RBX],
            reg[INTEL_X64_REGS::RCX], reg[INTEL_X64_REGS::RDX]);
        spdlog::debug("RSI {:16x} RDI {:16x} RIP {:16x} RSP {:16x}", 
            reg[INTEL_X64_REGS::RSI], reg[INTEL_X64_REGS::RDI],
            reg[INTEL_X64_REGS::RIP], reg[INTEL_X64_REGS::RSP]);
        spdlog::debug("R8  {:16x} R9  {:16x} R10 {:16x} R11 {:16x}", 
            reg[INTEL_X64_REGS::R8], reg[INTEL_X64_REGS::R9],
            reg[INTEL_X64_REGS::R10], reg[INTEL_X64_REGS::R11]);
        spdlog::debug("R12 {:16x} R13 {:16x} R14 {:16x} R15 {:16x}", 
            reg[INTEL_X64_REGS::R12], reg[INTEL_X64_REGS::R13],
            reg[INTEL_X64_REGS::R14], reg[INTEL_X64_REGS::R15]);
        spdlog::debug("EFLAGS  {:16x}", reg[INTEL_X64_REGS::EFLAGS]);
        spdlog::debug("FS  {:16x} GS  {:16x} ES  {:16x} DS  {:16x}", 
            reg[INTEL_X64_REGS::FS], reg[INTEL_X64_REGS::GS],
            reg[INTEL_X64_REGS::ES], reg[INTEL_X64_REGS::DS]);
        spdlog::debug("---------------------------------[ REGISTERS STOP  ]--------------------------------");
    }
};


class RemoteMemory {

    pid_t m_pid;

public:

    RemoteMemory(pid_t tracee_pid) : m_pid(tracee_pid) {}
    
    UserRegs* getGPRegisters() {
        struct iovec io;
        struct user_regs_struct* regs = (struct user_regs_struct*)malloc(sizeof(struct user_regs_struct));
        io.iov_base = regs;
        io.iov_len = sizeof(struct user_regs_struct);

        int ret = ptrace(PTRACE_GETREGSET, m_pid, (void*)NT_PRSTATUS, (void*)&io);
        if (ret < 0) {
            spdlog::error("Unable to get tracee [pid : {}] register, Err code: ", m_pid, ret);
            return nullptr;
        }
        UserRegs* tregs = UserRegs::createGP(io.iov_base, io.iov_len);
        // tregs->print();
        free(regs);
        return tregs;
    }

    int setGPRegisters(UserRegs* regs) {
        struct iovec io;
        io.iov_base = regs->reg;
        io.iov_len = sizeof(struct user_regs_struct);
        int ret = ptrace(PTRACE_SETREGSET, m_pid, (void*)NT_PRSTATUS, (void*)&io);
        // regs->print();
        if (ret < 0) {
            spdlog::error("Unable to get tracee [pid : {}] register, Err code: ", m_pid, ret);
        }
        return ret;
    }
    
    int read(Addr *dest, size_t readSize) {
        
        unsigned int bytes_read = 0;
        long * read_addr = (long *) dest->r_addr;
        long * copy_addr = (long *) dest->addr;
        unsigned long ret;
        memset(dest->addr, '\0', readSize);

        do {
            ret = ptrace(PTRACE_PEEKTEXT, m_pid, (read_addr++), NULL);
            // printf("RD : %p\n", ret);
            *(copy_addr++) = ret;
            bytes_read += sizeof(long);
        } while(ret && bytes_read < (readSize - sizeof(long)));
        
        return bytes_read;

    }
    
    int write(Addr *data, size_t writeSize) {

        uint32_t bytes_write = 0;
        long * write_addr = (long *) data->r_addr;
        long * copy_addr = (long *) data->addr;
        long ret;
        
        do {
            ret = ptrace(PTRACE_POKEDATA, m_pid, (write_addr++), *(copy_addr++));
            // printf("WD : %lu \t", ret);
            bytes_write += sizeof(long);
            // printf("%lu %lu %d\n", bytes_write , (writeSize - sizeof(long)), ret > -1);
        } while((ret > -1 )&& bytes_write < (writeSize - sizeof(long)));
        
        return bytes_write;
    }

    int read_cstring() {
        return 0;
    }
};


#define BREAKPOINT_INST 0xcc;
#define NOP_INST 0x90;
#define BREAKPOINT_SIZE sizeof(uint64_t)
#include "spdlog/fmt/bin_to_hex.h"

class Breakpoint {

    bool m_enabled;
    uintptr_t m_addr;
    pid_t m_pid;
    // breakpoint instruction data is stored to the memory
    // later restored when brk pnt is hit
    Addr *m_backupData;
    RemoteMemory *m_remoteMemory;
    uint32_t m_count = 0;

public:
    std::string *m_label;

    ~Breakpoint() { 
        delete m_backupData;
        delete m_remoteMemory;
        delete m_label;
    }


    Breakpoint(uintptr_t bk_addr, pid_t tracee_pid, std::string* _label): m_addr(bk_addr),
        m_enabled(true), m_pid(tracee_pid), m_label(_label),
        m_backupData(new Addr(bk_addr, BREAKPOINT_SIZE)),
        m_remoteMemory(new RemoteMemory(tracee_pid)) {}

    void enable() {
        uint8_t backup;
        m_remoteMemory->read(m_backupData, BREAKPOINT_SIZE);
        backup = m_backupData->addr[0];
        m_backupData->addr[0] = BREAKPOINT_INST;
        m_remoteMemory->write(m_backupData, BREAKPOINT_SIZE);
        m_backupData->addr[0] = backup;
        m_enabled = true;
    }
    
    void printDebug() {
        spdlog::trace("BRK [0x{:x}] [{}] pid {} count {} ", m_addr, m_label->c_str(), m_pid, m_count);
    }

    uint32_t getHitCount() {
        return m_count;
    }

    void handle() {
        m_count++;
        printDebug();
    }

    void disable() {
        m_remoteMemory->write(m_backupData, BREAKPOINT_SIZE);
        m_backupData->clean();
        m_enabled = false;
    }

    bool isEnabled() {
        return m_enabled;
    }

};

class BreakpointMngr {

    // this map will have pair of module name and
    // offset within the module where the breakpoint 
    // has to be placed
    map<std::string, vector<uintptr_t>> m_pending;

    map<uintptr_t, Breakpoint*> m_placed;
    ProcessMap* m_procMap;
    pid_t m_pid;

    // this is brk point is saved to restore the breakpoint
    // once it has executed, if there is no breakpoint has 
    // hit then this value should be null
    Breakpoint * m_suspendedBrkPnt = nullptr;

public:

    BreakpointMngr(pid_t tracee_pid, ProcessMap* procMap):
        m_pid(tracee_pid), m_procMap(procMap) {}

    // add breakpoint in format module@addr1,addr2,add3
    void addModuleBrkPnt(std::string& brk_mod_addr) {
        vector<uintptr_t> brk_offset;
        spdlog::trace("BRK {}", brk_mod_addr.c_str());
        
        auto mod_idx = brk_mod_addr.find("@");
        std::string mod_name = brk_mod_addr.substr(0, mod_idx);
        spdlog::trace("Module {}", mod_name.c_str());
        
        int pnt_idx = mod_idx, prev_idx = mod_idx;
        while(pnt_idx > 0) {
            prev_idx = pnt_idx + 1;
            pnt_idx = brk_mod_addr.find(",", prev_idx);
            uint64_t mod_offset = 0;
            if(pnt_idx > 0)
                mod_offset = stoi(brk_mod_addr.substr(prev_idx, pnt_idx - prev_idx), 0, 16);
            else 
                mod_offset = stoi(brk_mod_addr.substr(prev_idx), 0, 16);
            spdlog::trace("  Off {:x}", mod_offset);
            brk_offset.push_back(mod_offset);
        }
        m_pending.insert(make_pair(mod_name, brk_offset));
    }

    // put all the pending breakpoint in the tracee    
    void inject() {
        m_procMap->print();
        spdlog::debug("yeeahh... injecting all the pending Breakpoint!");

        for (auto i = m_pending.begin(); i != m_pending.end(); i++) {
            std::string mod_name = i->first;
            auto mod_base_addr = m_procMap->findModuleBaseAddr(mod_name);
            for(auto mod_offset: i->second) {
                // std::ostringstream stringStream;
                // stringStream << mod_name << "@" << mod_offset;
                // std::string copyOfStr = stringStream.str();
                char buff[100];
                snprintf(buff, sizeof(buff), "%s@%lx", mod_name.c_str(), mod_offset);
                auto x = new std::string(buff);
                setBreakpointAtAddr(mod_base_addr + mod_offset, x);
            }
        }
    }

    Breakpoint* getBreakpointObj(uintptr_t bk_addr) {
        auto brk_pnt_iter = m_placed.find(bk_addr);
        if (brk_pnt_iter != m_placed.end()) {
            // breakpoint is found, its under over management
            auto brk_obj = brk_pnt_iter->second;
            return brk_obj;
        } else {
            spdlog::warn("No Breakpoint object found! This is very unusual!");
            return nullptr;
        }
    }

    bool hasSuspendedBrkPnt() {
        return m_suspendedBrkPnt != nullptr;
    }

    void restoreSuspendedBreakpoint() {
        if (m_suspendedBrkPnt != nullptr) {
            spdlog::debug("Restoring breakpoint and resuming execution!");
            m_suspendedBrkPnt->enable();
            m_suspendedBrkPnt = nullptr;
        }
    }

    void handleBreakpointHit(uintptr_t brk_addr) {
        // PC points to the next instruction after execution
        spdlog::trace("Breakpoint Hit! addr 0x{:x}", brk_addr);
        // find the breakpoint object for further processing
        auto brk_obj = getBreakpointObj(brk_addr);
        m_suspendedBrkPnt = brk_obj;
        
        brk_obj->handle();

        // spdlog::debug("Brkpnt obj found!");
        // restore the value of original breakpoint instruction
        brk_obj->disable();
        
    }

    void printStats() {
        spdlog::info("------[ Breakpoint Stats ]-----");
        for (auto i = m_placed.begin(); i != m_placed.end(); i++) {
            auto brk_pt = i->second;
            spdlog::info("{} {}", brk_pt->m_label->c_str(), brk_pt->getHitCount());
        }
        spdlog::info("[------------------------------");
    }

    void setBreakpointAtAddr(uintptr_t brk_addr, std::string* label) {
        Breakpoint* brk_pnt_obj = new Breakpoint(brk_addr, m_pid, label);
        brk_pnt_obj->enable();
        m_placed.insert(make_pair(brk_addr, brk_pnt_obj));
    }
};
