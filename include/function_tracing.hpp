#include <string>

class TraceeProgram;

enum FunctionTraceErr {
    RESULT_OK = 0,
    
    /// @brief keep tracing the function
    CONT_TRACING,

    /// @brief You don't want to tracing the function anymore
    EXIT_TRACING,

    /// @brief Problem while placing breakpoint
    ERR_BREAKPOINT,
};

/// @brief Different type of tracing support by Function Tracing API
enum FuncTraceType {
    /// @brief Trace only the entry point of the function
    ONLY_ENTRY = 0,

    /// @brief Trace only the exit point
    ONLY_EXIT,

    /// @brief Trace both entry and exit point of the function
    ENTRY_EXIT,

    /// @brief trace all the basic block between the entry point and the exit point of the fuction
    BASIC_BLOCK,
};

enum FuncTraceState {
    NO_HIT = 0,
    ENTRY,
    EXIT
};

/**
 * This API helps you the trace function at various granularity 
 * like entry, exit and basic block.
 * Entry and exit tracing is helpful to observe the parameter while,
 * basic block tracing can help you understand different code paths
 * taken in various scenarios.
 */
class FunctionTracer {

    // This should be set at per thread level
    FuncTraceState m_state = FuncTraceState::NO_HIT;

    /// @brief different type of tracing supported byt 
    FuncTraceType m_trace_type = FuncTraceType::ENTRY_EXIT;

public:

    FunctionTracer(std::string& modname, uintptr_t entry_addr, uintptr_t exit_addr){}

    /// @brief Install the breakpoint needed for tracing the function
    void setup() {
        /**
         * 1. Create breakpoints for all the point in the function you
         *    are interested in tracing. In the most simple case two breakpoint
         *    one for function entry and other for the exit.
         * 2. In the breakpoint handle class call the `onExecute` function 
         *    is called which will have the logic to nagivate the tracing state,
         *    this needs consider for different threads.
         */
    }

    /// @brief Clear the breakpoint placed for tracing
    void clean();

    /// @brief This function is called when the any of the breakpoint related to this function is hit
    /// @return 
    FunctionTraceErr onExecute(TraceeProgram &traceeProg) {
        FunctionTraceErr result = FunctionTraceErr::RESULT_OK;
        switch (m_state)
        {
        case FuncTraceState::NO_HIT :
            result = onEntry(traceeProg);
            break;
        case FuncTraceState::EXIT:
            result = onEntry(traceeProg);
            break;
        case FuncTraceState::ENTRY:
            result = onEntry(traceeProg);
            break;
        default:
            break;
        }

        return result;
    }
    
    /// @brief Callback function when the function enter
    /// @param traceeProg 
    /// @return 
    virtual FunctionTraceErr onEntry(TraceeProgram &traceeProg) {
        return FunctionTraceErr::EXIT_TRACING;
    }

    /// @brief Callback function for every basic block executed in this thread.
    /// @param traceeProg Thread with is executing this code
    /// @return 
    virtual FunctionTraceErr onBasicBlock(TraceeProgram &traceeProg) {
        return FunctionTraceErr::EXIT_TRACING;
    }

    /// @brief Callback function when the function exits
    /// @param traceeProg 
    /// @return 
    virtual FunctionTraceErr onExit(TraceeProgram &traceeProg) {
        return FunctionTraceErr::EXIT_TRACING;
    }
};