#include "registers.hpp"


template <class T> T IRegisters<T>::getRegIdx(uint8_t reg_idx) {
    return reinterpret_cast<T *>(m_gp_reg_data)[reg_idx];
}

template <class T> T IRegisters<T>::setRegIdx(uint8_t reg_idx, T value) {
    reinterpret_cast<T *>(m_gp_reg_data)[reg_idx] = value;
}

template <class T> T IRegisters<T>::getProgramCounter() {
    // PC register points to the next instruction
    return getRegIdx(program_register_idx);
}

template <class T> void IRegisters<T>::setProgramCounter(T reg_val) {
    reinterpret_cast<T *>(m_gp_reg_data)[program_register_idx] = reg_val;
}

template <class T> T IRegisters<T>::getStackPointer() {
    return getRegIdx(stack_pointer_register_idx);
}
