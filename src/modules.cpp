#include <vector>
#include <iostream>
#include <algorithm>
#include <dirent.h>
#include "modules.hpp"

uint8_t ProcessMap::praseMapPermission(char const *perms)
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

uintptr_t ProcessMap::findModuleBaseAddr(std::string &module_path) {
    auto val = std::find_if(
        std::begin(m_map),
        std::end(m_map),
        [module_path](ProcMap* proc_map) -> bool {
            if (module_path.size() > proc_map->path->size())
                return false;
            return std::equal(
                module_path.rbegin(), module_path.rend(),
                proc_map->path->rbegin()
            );
        }
    );
    if (val != std::end(m_map)) {
        m_log->debug("Find mod : {} base addr : 0x{:x}", (*val)->path->c_str(), (*val)->addr_begin);
        return (*val)->addr_begin;
    }
    m_log->error("Module '{}' not found!", module_path.c_str());
    return 0;
}

void ProcessMap::parseLine(char *line)
{
    ProcMap *proc_map_obj = new ProcMap;
    char *pathname_token = NULL;
    // m_log->debug("Parseline {}", line);
    proc_map_obj->addr_begin = strtoull(strtok(line, "-"), NULL, 16);
    proc_map_obj->addr_end = strtoull(strtok(NULL, " "), NULL, 16);
    proc_map_obj->perms = praseMapPermission(strtok(NULL, " "));
    proc_map_obj->offset = strtoull(strtok(NULL, " "), NULL, 16);
    proc_map_obj->dev.major = atoi(strtok(NULL, ":"));
    proc_map_obj->dev.minor = atoi(strtok(NULL, " "));
    proc_map_obj->inode = atoi(strtok(NULL, " "));
    pathname_token = strtok(NULL, " \n");

    if (pathname_token != NULL) {
        proc_map_obj->path = new std::string(pathname_token);
    } else {
        // m_log->debug("We should resturn from here");
        proc_map_obj->path = new std::string("no-file");
    }
    m_map.push_back(proc_map_obj);
}


void ProcessMap::parseProcessMapFile(FILE *procmaps_file)
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
        m_log->warn("Error while parsing process file!");
        // destroy_procmaps(procmaps_array);
        // return NULL;
    }
}

int ProcessMap::parse()
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
        m_log->error("error opening proc/{}/maps file!", m_pid);
        return -1;
    }
    parseProcessMapFile(procmaps_file);
    errno_saver = errno;
    if (fclose(procmaps_file) != -1)
        errno = errno_saver;
    return 0;
}

void ProcessMap::permStr(uint8_t perm_val, char * pem_str) {
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
    // m_log->debug("PEM {} {}", perm_val, pem_str);
}

void ProcessMap::list_child_threads() {
    DIR *dr;
    struct dirent *en;
    std::string thead_dir = spdlog::fmt_lib::format("/proc/{}/task", m_pid);
    dr = opendir(thead_dir.c_str()); //open all or present directory

    if (dr) {
        while ((en = readdir(dr)) != NULL) {
            if(!strcmp(en->d_name, ".") || !strcmp(en->d_name, ".."))
                continue;
            m_child_thread_pids.push_back(atoi(en->d_name));
        }
        closedir(dr); //close all directory
    }
}

void ProcessMap::print() {
    m_log->debug("----------------[ PROCESS MAP ]----------------");
    char pem_str[5];
    for (auto ir : m_map) {
        memset(pem_str, '-', sizeof(pem_str) -1 );
        pem_str[5] = '\x0';
        permStr(ir->perms, pem_str);
        m_log->debug("{:x} {:x} {} {}", ir->addr_begin, ir->addr_end, pem_str, ir->path->c_str());
    }
    m_log->debug("----------------[     END     ]----------------");
}

