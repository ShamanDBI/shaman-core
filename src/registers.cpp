#include "registers.hpp"



template <class T> Registers<T>::~Registers() {
    free(reinterpret_cast<T *>(gp_reg));
}

template <class T> Registers<T>::Registers(pid_t tracee_pid, uint8_t reg_cnt) : m_pid(tracee_pid) {
    m_gp_reg_count = reg_cnt;
    gp_reg_size = sizeof(T) * m_gp_reg_count; //ARCH_GP_REG_CNT;
    gp_reg = reinterpret_cast<uintptr_t>(malloc(gp_reg_size));
}

template <class T> T Registers<T>::getRegIdx(uint8_t reg_idx) {
    return reinterpret_cast<T *>(gp_reg)[reg_idx];
}

template <class T> T Registers<T>::setRegIdx(uint8_t reg_idx, T value) {
    reinterpret_cast<T *>(gp_reg)[reg_idx] = value;
}

template <class T> T Registers<T>::getProgramCounter() {
    // PC register points to the next instruction
    return getRegIdx(program_register_idx);
}

template <class T> void Registers<T>::setProgramCounter(T reg_val) {
    reinterpret_cast<uint64_t *>(gp_reg)[program_register_idx] = reg_val;
}

template <class T> T Registers<T>::getStackPointer() {
    return getRegIdx(stack_pointer_register_idx);
}
