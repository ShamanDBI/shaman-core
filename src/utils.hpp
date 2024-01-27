#ifndef _UTILS_H
#define _UTILS_H
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/fmt/bin_to_hex.h"

/**
 * @brief Simple Random Number Generator
 * 
 * Example Usage :
 *  Rand randomGenerator(0xcafebabedeadbeef);
 *   
 *  int count = 0;
 *  while(count < 10) {
 *  	spdlog::warn("Rand {:x} {:x} {:x} {:x}", randomGenerator.u8(),
 *  		randomGenerator.u16(),
 *  		randomGenerator.u32(),
 *  		randomGenerator.u64());
 *  	count++;
 *  } 
 */
class Rand {
	
	uint64_t m_seed = 0;

	uint64_t _genRand() {
		uint64_t seed = m_seed;
		seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 43;
		m_seed = seed;
		return seed;
	}

public:

	Rand(uint64_t seed) {
		m_seed = seed;
	}

	uint8_t u8() {
		return _genRand() & 0xff;
	}

	uint16_t u16() {
		return _genRand() & 0xffff;
	}

	uint32_t u32() {
		return _genRand() & 0xffffffff;
	}

	uint64_t u64() {
		return _genRand();
	}

    /**
     * @brief Fill the buffer with Random Data
     * 
     * @param buffer Pointer to the buffer you wish to fill the random data
     * @param buffer_size Size of the buffer you want to fill
     */
    void fillBuffer(uint8_t* buffer, uint64_t buffer_size) {
        // spdlog::error("{}", buffer_size);
        uint8_t* curr_ptr = buffer;
        uint32_t buf_idx = buffer_size / sizeof(uint64_t);
        uint32_t buf_unfil = buffer_size % sizeof(uint64_t);
        uint32_t count = 0;
        
        while(count < buf_idx) {
            *reinterpret_cast<uint64_t*>(curr_ptr) = u64();
            // spdlog::error("dd da {:x}", *curr_ptr);
            curr_ptr += sizeof(uint64_t);
            count++;
        }
        
        if(buf_unfil) {
            buf_idx = buf_unfil / sizeof(uint32_t);
            buf_unfil = buf_unfil % sizeof(uint32_t);
            count = 0;
            // spdlog::error("dd {}", buf_idx);
                
            while(count < buf_idx) {
                *reinterpret_cast<uint32_t *>(curr_ptr) = u32();
                // spdlog::error("dd da {:x}", *curr_ptr);
                curr_ptr += sizeof(uint32_t);
                count++;
            }
        }
        
        // spdlog::error("aa {}", buf_unfil);
        if(buf_unfil) {
            count = 0;
            while(count < buf_unfil) {
            // spdlog::error("{}", buf_unfil);
                *curr_ptr = u8();
                // spdlog::error("aa ba {:x}", *curr_ptr);
                curr_ptr++;
                count++;
            }
        }
    }
};

#endif