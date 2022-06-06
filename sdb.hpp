#ifndef __GDB__
#define __GDB__

// c lib
#include <sys/types.h>
#include <unistd.h>

// c++ lib
#include <string>
#include <vector>
#include <fstream>

// constant
#define SDB_STATE_INIT              0x00000000
#define SDB_STATE_PROGRAM_LOADED    0x00000001
#define SDB_STATE_HAVE_SCRIPT       0x00000002
#define SDB_STATE_PROCESS_RUNNING   0x00000004

#define SDB_STATE_CLOSED            0xF0000000

#define SDB_BACKUP_ELF              0           // default is off

// macro
#define SDB_IS_LOADED(state)    ((state&SDB_STATE_PROGRAM_LOADED)>0)
#define SDB_IS_RUNING(state)    ((state&SDB_STATE_PROCESS_RUNNING)>0)
#define SDB_HAS_SCRIPT(state)   ((state&SDB_STATE_HAVE_SCRIPT)>0)
#define SDB_IS_CLOSED(state)    ((state&SDB_STATE_CLOSED)>0)

namespace sdb{
    // type
    typedef int state_t;

    typedef std::vector<char> elf_t;

    struct elf_header
    {
        int cla;
        long enter_point=0;
    };
    

    class SDebugger{
        public:
            void assign_script(const std::string&  path);
            void fetch_command();
            void exec_command();
            
            // instructions
            bool cont();
            void exit();
            void help()const;
            bool load(const std::string& cmd);
            bool run();
            bool start();
            // state
            inline bool state_loaded()const{return SDB_IS_LOADED(state);}
            inline bool state_running()const{return SDB_IS_RUNING(state);}
            inline bool is_closed()const{return SDB_IS_CLOSED(state);}
        private:
            void handle_status(const int status);

            state_t state = SDB_STATE_INIT;
            std::ifstream script_stream;
            std::string command = std::string("");
            elf_t elf;
            elf_header elf_hdr;
            std::string program_file;
            pid_t child_process;
    };
}

#endif