#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <vector>
#include <spdlog/spdlog.h>
#include <iostream>
#include <algorithm>

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
    std::string *pathname = nullptr;

};


class ProcessMap {

    std::vector<ProcMap*> m_map;
    pid_t m_pid;

public:
    ProcessMap(pid_t tracee_pid): m_pid(tracee_pid) {
        m_map.reserve(32);
    }
    
    uint8_t praseMapPermission(char const *perms)
    {
        uint8_t perm = 0x00;

        if (perms[0] == 'r') {
            perm |= ProcMap::PERMS_READ;
        }
        if (perms[1] == 'w') {
            perm |= ProcMap::PERMS_WRITE;
        }
        if (perms[2] == 'x') {
            perm |= ProcMap::PERMS_EXECUTE;
        }
        if (perms[3] == 'p') {
            perm |= ProcMap::PERMS_PRIVATE;
        } else if (perms[3] == 's') {
            perm |= ProcMap::PERMS_SHARED;
        }
        return perm;
    }

    uintptr_t findModuleBaseAddr(std::string &module_path) {
        auto val = std::find_if(
            std::begin(m_map),
            std::end(m_map),
            [module_path](ProcMap* proc_map) -> bool {
                if (module_path.size() > proc_map->pathname->size())
                    return false;
                return std::equal(
                    module_path.rbegin(), module_path.rend(),
                    proc_map->pathname->rbegin()
                );
            }
        );
        if (val != std::end(m_map)) {
            spdlog::debug("Find mod : {} base addr : 0x{:x}", (*val)->pathname->c_str(), (*val)->addr_begin);
            return (*val)->addr_begin;
        }
        spdlog::error("Module '{}' not found!", module_path.c_str());
        return 0;
    }

    void parseLine(char *line)
    {
        ProcMap *proc_map_obj = new ProcMap;
        char *pathname_token = NULL;

        proc_map_obj->addr_begin = strtoull(strtok(line, "-"), NULL, 16);
        proc_map_obj->addr_end = strtoull(strtok(NULL, " "), NULL, 16);
        proc_map_obj->perms = praseMapPermission(strtok(NULL, " "));
        proc_map_obj->offset = strtoull(strtok(NULL, " "), NULL, 16);
        proc_map_obj->dev.major = atoi(strtok(NULL, ":"));
        proc_map_obj->dev.minor = atoi(strtok(NULL, " "));
        proc_map_obj->inode = atoi(strtok(NULL, " "));
        pathname_token = strtok(NULL, " \n");

        if (pathname_token != NULL) {
            proc_map_obj->pathname = new std::string(pathname_token);
            // if (proc_map_obj->pathname == NULL) {
            //     return;
            // }
        } else {
            proc_map_obj->pathname = nullptr;
        }
        m_map.push_back(proc_map_obj);
    }


    void parseProcessMapFile(FILE *procmaps_file)
    {
        size_t size = 0;
        char *line = NULL;

        while (getline(&line, &size, procmaps_file) != -1) {
            if (line != NULL)
                parseLine(line);
            free(line);
            line = NULL;
            size = 0;
        }

        free(line);
        
        if (errno == EINVAL || errno == ENOMEM) {
            spdlog::warn("Error while parsing process file!");
            // destroy_procmaps(procmaps_array);
            // return NULL;
        }
    }
    
    int parse()
    {
        char path[100];
        FILE *procmaps_file = NULL;
        int errno_saver = 0;

        if (m_pid <= 0) {
            strcpy(path, "/proc/self/maps");
        } else {
            sprintf(path, "/proc/%d/maps", m_pid);
        }
        procmaps_file = fopen(path, "r");

        if (procmaps_file == NULL) {
            spdlog::error("error opening proc/{}/maps file!", m_pid);
            return -1;
        }
        parseProcessMapFile(procmaps_file);
        errno_saver = errno;
        if (fclose(procmaps_file) != -1)
            errno = errno_saver;
        return 0;
    }
    
    void permStr(uint8_t perm_val, char * pem_str) {
        if (perm_val & ProcMap::PERMS_READ) {
            pem_str[0]='r';
        } 
        
        if (perm_val & ProcMap::PERMS_WRITE) {
            pem_str[1]='w';
        } 
        
        if (perm_val & ProcMap::PERMS_EXECUTE) {
            pem_str[2]='x';
        } 
        
        if (perm_val & ProcMap::PERMS_PRIVATE) {
            pem_str[3]='p';
        } 

        if (perm_val & ProcMap::PERMS_SHARED) {
            pem_str[3]='s';
        } 
        // spdlog::debug("PEM {} {}", perm_val, pem_str);
    }

    void print() {
        spdlog::debug("----------------[ PROCESS MAP ]----------------");
        char pem_str[5];
        for (auto ir : m_map) {
            memset(pem_str, '-', sizeof(pem_str) -1 );
            pem_str[5] = '\x0';
            permStr(ir->perms, pem_str);
            spdlog::debug("{:x} {:x} {} {} ", ir->addr_begin, ir->addr_end, pem_str, ir->pathname->c_str());
        }
        spdlog::debug("----------------[     END     ]----------------");
    }

};

