#ifndef H_PROC_MODULE
#define H_PROC_MODULE

#include <cstdint>
#include <string>

// using namespace std;
/**
 * @brief Hold the major minor id for the map's device
 */
struct dev_major_minor_t {
    int major;
    int minor;
};


/**
 * @brief Hold all the information of a map
 */
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


class ProcessMap {

    std::vector<ProcMap*> m_map;
    pid_t m_pid;

public:
    
    ProcessMap(pid_t tracee_pid): m_pid(tracee_pid) {
        m_map.reserve(32);
    }

    uint8_t praseMapPermission(char const *perms);
	uintptr_t findModuleBaseAddr(std::string &module_path);
	void parseLine(char *line);
	void parseProcessMapFile(FILE *procmaps_file);
	int parse();
	void permStr(uint8_t perm_val, char * pem_str);
	void print();
    
};

#endif