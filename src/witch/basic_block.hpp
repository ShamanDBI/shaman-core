#pragma once
#include <vector>

struct cs_insn;

using addr_t = size_t;

/**
 * @brief a lightweight container for data relevant to basic blocks contained in
 * a maximal block.
 */
class BasicBlock {
public:
    /**
     * Construct a BasicBlock that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    BasicBlock(uint64_t id, cs_insn *inst);
    
    addr_t addressAt(unsigned index) const;

    size_t id() const;
    bool isValid() const;
    const size_t size() const;

    bool isAppendableBy(const cs_insn *inst) const;
    bool isAppendableAt(const addr_t addr) const;
    size_t instructionCount() const;
    addr_t startAddr() const;
    addr_t endAddr() const;
    const std::vector<addr_t> &getInstructionAddresses() const;
    void append(cs_insn *inst);

    bool isConditional() const noexcept { return m_conditional_branch; }
    bool isDirect() const noexcept { return m_direct_branch; }
    bool isCall() const noexcept { return m_is_call; }
    
    void addTarget(std::vector<intptr_t>* _branch_targets) { 
        m_target = _branch_targets;
    }

    intptr_t target() { return m_target->front(); };

private:
    bool m_valid;
    size_t m_id; // Basic Block ID
    size_t m_size; // Size of basic block
    bool m_direct_branch;
    bool m_conditional_branch;
    bool m_is_call;
    std::vector<intptr_t>* m_target;
    std::vector<addr_t> m_inst_addrs;
};

