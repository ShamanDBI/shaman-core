#include <ShamanDBA/config.hpp>
#include <CLI/CLI.hpp>

#include "spdlog/spdlog.h"

#include "ShamanDBA/mempipe.hpp"

struct coverage_module
{
    uint16_t rec_type;
    char module_name[300];
    uint16_t module_id;
};

struct cov_data
{
    uint16_t rec_type;
    uint16_t module_id;
    uint32_t tracee_pid;
    uint32_t exec_offset;
};

void PrintModuleInfo(coverage_module *mod_info)
{
    printf("Mod Info - %d %s\n", mod_info->module_id, mod_info->module_name);
}

void PrintCoverageRec(cov_data *rec_data) {
    printf("Cov %u %u %u %x\n", rec_data->rec_type, rec_data->tracee_pid, rec_data->module_id, rec_data->exec_offset);
}

int CoverageProcessor(uint8_t *buffer, uint32_t buffer_len)
{
    printf("Processing Data : ptr %p of len %d\n", buffer, buffer_len);

    uint16_t rec_type = *reinterpret_cast<uint16_t *>(buffer);
    coverage_module mod_info = {0};
    cov_data cov_rec = {0};
    uint32_t read_count = 0;
    uint32_t cov_point_count = 0;
    if (rec_type == 0)
    {
        // module info
        memset(&mod_info, 0, sizeof(coverage_module));
        buffer += sizeof(uint16_t);
        uint16_t mod_size = *reinterpret_cast<uint16_t *>(buffer);
        buffer += sizeof(uint16_t);
        memcpy(&mod_info.module_name, buffer, mod_size);
        buffer += mod_size;
        mod_info.module_id = *reinterpret_cast<uint16_t *>(buffer);
        buffer += sizeof(uint16_t);
        PrintModuleInfo(&mod_info);
    }
    else
    {
        while (read_count < buffer_len)
        {
            // coverage info
            memset(&cov_rec, 0, sizeof(cov_data));
            cov_rec.rec_type = *reinterpret_cast<uint16_t *>(buffer + read_count);
            read_count += sizeof(uint16_t);
            cov_rec.module_id = *reinterpret_cast<uint16_t *>(buffer + read_count);
            read_count += sizeof(uint16_t);
            cov_rec.tracee_pid = *reinterpret_cast<uint32_t *>(buffer + read_count);
            read_count += sizeof(uint32_t);
            cov_rec.exec_offset = *reinterpret_cast<uint32_t *>(buffer + read_count);
            read_count += sizeof(uint32_t);
            PrintCoverageRec(&cov_rec);
            cov_point_count += 1;
        }
        printf("Total coverage points : %u\n", cov_point_count);
    }

    return 0;
}

void CoverageConsumer(uint64_t pipe_id)
{

    spdlog::info("Started");
    auto rec_pipe = new RecvPipe<DEFAULT_CHUNK_SIZE, DEFAULT_NUM_BUFFER>();
    MemPipeError res = rec_pipe->open(pipe_id);
    if (res != MemPipeError::ResultOk)
    {
        spdlog::error("Shared Memory Error Id");
        return;
    }

    Ticket tk = rec_pipe->requestTicket();
    Ticket new_tk = 0;
    while (1)
    {
        sleep(3);
        rec_pipe->try_recv(tk, &CoverageProcessor, &new_tk);
        if (tk != new_tk)
        {
            spdlog::info("New Ticket Id : {}", new_tk);
        }
        tk = new_tk;
    }
}

int main(int argc, char **argv)
{
    int64_t shm_pipe_id = 0xcafe;
    spdlog::info("This is Coverage consumer library");

    CoverageConsumer(shm_pipe_id);

    return 0;
}