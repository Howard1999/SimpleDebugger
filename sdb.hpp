#ifndef __SDB__
#define __SDB__

// c lib
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
#include <elf.h>

// c++ lib
#include <string>
#include <vector>
#include <fstream>
#include <map>

// cpastone
#include <capstone/capstone.h>

// constant
#define SDB_STATE_INIT              0x00000000
#define SDB_STATE_PROGRAM_LOADED    0x00000001
#define SDB_STATE_HAVE_SCRIPT       0x00000002
#define SDB_STATE_PROCESS_RUNNING   0x00000004

#define SDB_STATE_CLOSED            0xF0000000

#define SDB_TEXT_BYTE_MASK          0x00000000000000FF

#define SDB_MSG_LOAD                        "program '%s' loaded. entry point 0x%llx"
#define SDB_MSG_BREAKPOINT                  "breakpoint @ %llx"
#define SDB_MSG_NORMAL_TERMINATE            "child process %d terminiated normally (code 0)"
#define SDB_MSG_ABNORMAL_TERMINATE          "child process %d terminiated abnormally (code %d)"
#define SDB_REGISTER_VALUE                  "%s = %llu(0x%llx)"

#define WARNING_MSG_ALREADY_RUNNING         "program '%s' is already running"

#define ERR_MSG_UNKNOWN_INSTRUCTION         "unknown instruction"
#define ERR_MSG_PROGRAM_NOT_RUNNING         "program is not running"
#define ERR_MSG_ADDRESS_OUT_OF_TEXT         "the address is out of the range of the text segment"
#define ERR_MSG_BREAKPOINT_EXIST            "breakpoint already exist"
#define ERR_MSG_SET_BREAKPOINT_FAILED       "set breakpoint failed"
#define ERR_MSG_RECOVER_BREAKPOINT_FAILED   "recover breakpoint failed"
#define ERR_MSG_RECOVER_INSTRUCTION_FAILED  "recover instruction failed"
#define ERR_MSG_INDEX_OUT_OF_RANGE          "index out of range"
#define ERR_MSG_DELETE_BREAKPOINT_FAILED    "delete breakpoint failed"
#define ERR_MSG_FILE_IS_NOT_ELF             "file is not an elf"
#define ERR_MSG_LOAD_MULTIPLE_TIMES         "program '%s' has been loaded, cannot load again"
#define ERR_MSG_OPEN_FAILED                 "file: '%s' open failed"
#define ERR_MSG_PROGRAM_NOT_LOADED          "program is not loaded"
#define ERR_MSG_FORK_FAILED                 "fork failed"
#define ERR_MSG_CHILD_PROCESS_INIT_FAILED   "child process initialize failed"
#define ERR_MSG_UNKNOWN_REGISTER_NAME       "unknown register"
#define ERR_MSG_ADDRESS_NOT_GIVEN           "no addr is given"
#define ERR_MSG_UNKNOWN_ELF_CLASS           "unknown elf class, class only accept 1(32bit) and 2(64bit) elf file"
#define ERR_MSG_DISASM_FAILED               "disam failed"
#define ERR_MSG_UNKNOWN                     "unknown error happend"

// macro
#define SDB_IS_LOADED(state)    ((state&SDB_STATE_PROGRAM_LOADED)>0)
#define SDB_IS_RUNING(state)    ((state&SDB_STATE_PROCESS_RUNNING)>0)
#define SDB_HAS_SCRIPT(state)   ((state&SDB_STATE_HAVE_SCRIPT)>0)
#define SDB_IS_CLOSED(state)    ((state&SDB_STATE_CLOSED)>0)

namespace sdb{
    // type
    typedef int state_t;
    typedef struct user_regs_struct regs_t;

    class SDebugger{
        public:
            virtual ~SDebugger(){
                __close_disasm();
            }

            void assign_script(const std::string&  path);
            void fetch_command();
            void exec_command();
            
            // instructions
            bool set_breakpoint(const std::string& address);
            bool cont();
            bool delete_breakpoint(const std::string& id);
            void disasm(const std::string& address)const;
            void dump(const std::string& address)const;
            void exit();
            void getreg(const std::string& reg)const;
            void getregs()const;
            void help()const;
            void list()const;
            bool load(const std::string& cmd);
            bool run();
            void vmmap()const;
            bool setreg(const std::string& args);
            bool step_ins();
            bool start();
            // state
            inline bool state_loaded()const{return SDB_IS_LOADED(state);}
            inline bool state_running()const{return SDB_IS_RUNING(state);}
            inline bool is_closed()const{return SDB_IS_CLOSED(state);}
        private:
            void __getregs(regs_t&)const;
            void __setregs(const regs_t& regs);
            unsigned long __peek_code(unsigned long addr)const;
            bool __poke_byte_code(unsigned long addr, unsigned long code);
            bool __is_breakpoint(unsigned long addr)const;
            bool __set_breakpoint(unsigned long addr);
            bool __unset_breakpoint(unsigned long addr);
            void __child_terminate();
            bool __init_disasm();
            void __close_disasm();
            cs_insn* __disasm();

            void __setup_all_breakpoint();

            state_t state = SDB_STATE_INIT;
            int child_status;

            std::ifstream script_stream;
            std::string command = std::string("");

            int8_t elf_cla;
            Elf32_Ehdr hdr32;
            Elf64_Ehdr hdr64;
            unsigned long text_sec_min_addr; // entry point
            unsigned long text_sec_max_addr;

            std::string program_file;
            pid_t child_process;

            std::vector<unsigned long> breakpoints_addrs;
            std::map<unsigned long, unsigned long>breakpoints;

            csh cs_handler;
    };
}

#endif