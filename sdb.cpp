#include <sys/ptrace.h>
#include <sys/wait.h>

#include <iostream>
#include <sstream>

#include "sdb.hpp"

using namespace std;
using namespace sdb;

void err_msg(const string& msg){
    cout<<"** "<<msg<<endl;
}

void err_quit(const char *msg) {
	perror(msg);
	exit(-1);
}

void SDebugger::assign_script(const string& path){
    script_stream = ifstream(path.c_str());
    if(script_stream.peek()!=EOF){
        state |= SDB_STATE_HAVE_SCRIPT;
    }
}

void SDebugger::fetch_command(){
    istream* cmd_istream;
    if(SDB_HAS_SCRIPT(state)){ // read from script
        cmd_istream = &script_stream;
    }else{ // read from user input
        printf("sdb> ");
        cmd_istream = &cin;
    }
    
    getline(*cmd_istream, command);

    if(SDB_HAS_SCRIPT(state) && (script_stream.peek()==EOF)){
        state &= ~SDB_STATE_HAVE_SCRIPT;
    }
}

void SDebugger::exec_command(){
    if(command.size()<=0) return;

    // read instruction
    istringstream ss(command);
    string instruction, args;
    ss>>instruction;
    ss.ignore();
    getline(ss, args);

    if(instruction == "cont" || instruction == "c"){
        cont();
    }
    else if(instruction == "exit" || instruction == "q"){
        exit();
    }
    else if(instruction == "help" || instruction == "h"){
        help();
    }
    else if(instruction == "load"){
        load(args);
    }
    else if(instruction == "run" || instruction == "r"){
        run();
    }
    else if(instruction == "start"){
        start();
    }
    else{
        err_msg(string("unknown instrction"));
    }
}

bool SDebugger::cont(){
    if(SDB_IS_RUNING(state)){
        int status;
        ptrace(PTRACE_CONT, child_process, 0, 0);
        waitpid(child_process, &status, 0);

        if(WIFEXITED(status)){ // check terminate
            state &= ~SDB_STATE_PROCESS_RUNNING;
            const int es = WEXITSTATUS(status);
            char str[512]={};
            if(es==0){
                sprintf(str, "child process %d terminiated normally (code 0)", child_process);
            }else{
                sprintf(str, "child process %d terminiated abnormally (code %d)", child_process, es);
            }
            err_msg(str);
        }
        
        return true;
    }
    else{
        err_msg(string("cont: program is not running"));
        return false;
    }
}

void SDebugger::exit(){
    if(SDB_IS_RUNING(state)){
        kill(child_process, 9);
    }
    state |= SDB_STATE_CLOSED;
}

void SDebugger::help()const{
    cout<<"- break {instruction-address}: add a break point                         "<<endl;
    cout<<"- cont: continue execution                                               "<<endl;
    cout<<"- delete {break-point-id}: remove a break point                          "<<endl;
    cout<<"- disasm addr: disassemble instructions in a file or a memory region     "<<endl;
    cout<<"- dump addr: dump memory content                                         "<<endl;
    cout<<"- exit: terminate the debugger                                           "<<endl;
    cout<<"- get reg: get a single value from a register                            "<<endl;
    cout<<"- getregs: show registers                                                "<<endl;
    cout<<"- help: show this message                                                "<<endl;
    cout<<"- list: list break points                                                "<<endl;
    cout<<"- load {path/to/a/program}: load a program                               "<<endl;
    cout<<"- run: run the program                                                   "<<endl;
    cout<<"- vmmap: show memory layout                                              "<<endl;
    cout<<"- set reg val: get a single value to a register                          "<<endl;
    cout<<"- si: step into instruction                                              "<<endl;
    cout<<"- start: start the program and stop at the first instruction             "<<endl;
}

bool SDebugger::load(const string& path){
    if(SDB_IS_LOADED(state)){
        err_msg(string("load: program '")+program_file+string("' has loaded, cannot load again."));
        return false;
    }else{
        // open elf
        FILE* fp = fopen(path.c_str(), "r");
        if (fp == NULL){
            err_msg(string("load: open '")+path+string("' failed."));
            return false;
        }
        // check is elf and get type
        char tmp[5]={};
        fread(tmp, 1, 4, fp);
        if(tmp[0] != 0x7F || tmp[1] != 'E' || tmp[2] != 'L' || tmp[3] != 'F'){
            err_msg(string("load: file is not an elf."));
            return false;
        }
        elf_hdr.cla = tmp[4];
        // read enter point
        fseek(fp, 0x18, SEEK_SET);
        if(elf_hdr.cla==1){ // 32 bits
            int e;
            fread(&e, 4, 1, fp);
            elf_hdr.enter_point = e;
        }else{ // 64 bits
            long e;
            fread(&e, 8, 1, fp);
            elf_hdr.enter_point = e;
        }
        // back up whole elf
        if(SDB_BACKUP_ELF){
            fseek(fp, 0, SEEK_SET);
            char c;
            while (fread(&c, 1, 1, fp)==1)elf.push_back(c);
        }
        // load
        program_file = path;
        state |= SDB_STATE_PROGRAM_LOADED;
        char str[512]={};
        sprintf(str, "program '%s' loaded. entry point 0x%lx", program_file.c_str(), elf_hdr.enter_point);
        err_msg(string(str));
        return true;
    }
}

bool SDebugger::run(){
    err_msg(string("run: start + cont"));

    if(SDB_IS_LOADED(state)){
        if(SDB_IS_RUNING(state)){
            char str[512]={};
            sprintf(str, "program %s is already running", program_file.c_str());
            err_msg(string(str));
            cont();
        }
        else{
            start();
            cont();
        }
        return true;
    }
    else{
        err_msg(string("run: program is not loaded."));
        return false;
    }
}

bool SDebugger::start(){
    if(!SDB_IS_LOADED(state)){
        err_msg(string("start: program is not loaded."));
        return false;
    }
    else if(SDB_IS_RUNING(state)){
        err_msg(string("start: program is already running."));
        return false;
    }
    else if(SDB_IS_LOADED(state)){
        pid_t pid = fork();
        if(pid < 0){ // fork failed
            err_msg(string("start: fork failed"));
            return false;
        }
        else if(pid==0){ // child
            if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)err_quit("ptrace");
            if(execl(program_file.c_str(), "", nullptr))err_quit("execl");
        }else{
            child_process = pid;
            
            int status;
            if(waitpid(child_process, &status, 0)<0){
                err_msg(string("start: child process initialize failed"));
                return false;
            }
            if(WIFSTOPPED(status)){
                ptrace(PTRACE_SETOPTIONS, child_process, 0, PTRACE_O_EXITKILL);
                state |= SDB_STATE_PROCESS_RUNNING;
                char str[512]={};
                sprintf(str, "pid %d", child_process);
                err_msg(string(str));
                return true;
            }
            else{
                err_msg(string("start: unknown error happend"));
                return false;
            }
        }
    }
    return false;
}
