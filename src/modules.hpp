#ifndef H_PROC_MODULE
#define H_PROC_MODULE

#include <string>
#include "spdlog/spdlog.h"

struct dev_major_minor_t {
    int major;
    int minor;
};

struct ProcMap {
    enum MAPS_PERMS {
        PERMS_READ    = 1 << 0,
        PERMS_WRITE   = 1 << 1,
        PERMS_EXECUTE = 1 << 2,
        PERMS_PRIVATE = 1 << 3,
        PERMS_SHARED  = 1 << 4
    }; 
    uintptr_t addr_begin;
    uintptr_t addr_end;
    uint8_t perms;
    uint64_t offset;
    dev_major_minor_t dev;
    int32_t inode;
    std::string *path = nullptr;
};


/// @brief Information about the process map
class ProcessMap {

    std::vector<ProcMap*> m_map;
    pid_t m_pid;
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("main");
public:
    std::vector<pid_t> m_child_thread_pids;
    
    ProcessMap(pid_t tracee_pid): m_pid(tracee_pid) {
        m_map.reserve(32);
    };
    
    ProcessMap* setPid(pid_t tracee_pid) {
        m_pid = tracee_pid;
        return this;
    };

    uint8_t praseMapPermission(char const *perms);
	uintptr_t findModuleBaseAddr(std::string &module_path);
	void parseLine(char *line);
	void parseProcessMapFile(FILE *procmaps_file);
	
    /// @brief parses the process map from '/proc/<pid>/maps'
    int parse();
	void permStr(uint8_t perm_val, char * pem_str);
	void print();
    void list_child_threads();
    
};

#endif