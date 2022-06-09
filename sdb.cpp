#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <elf.h>

#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>

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

unsigned long hex2ul(const string& hex){
    char *stopstr;
    return strtoul(hex.c_str(), &stopstr, 16);
}

void to_lower_string(string& str){
    for(int i=0; i<(int)str.size(); i++){
        str[i] = tolower(str[i]);
    }
}

string remove_space(const string& str){
    string str_copy(str);
    str_copy.erase(remove(str_copy.begin(), str_copy.end(), ' '), str_copy.end());
    return str_copy;
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

    if(instruction == "break" || instruction == "b"){
        set_breakpoint(args);
    }
    else if(instruction == "cont" || instruction == "c"){
        cont();
    }
    else if(instruction == "delete"){
        delete_breakpoint(args);
    }
    else if(instruction == "disasm" || instruction == "d"){
        disasm(args);
    }
    else if(instruction == "dump" || instruction == "x"){
        dump(args);
    }
    else if(instruction == "exit" || instruction == "q"){
        exit();
    }
    else if(instruction == "get" || instruction == "g"){
        getreg(args);
    }
    else if(instruction == "getregs"){
        getregs();
    }
    else if(instruction == "help" || instruction == "h"){
        help();
    }
    else if(instruction == "list" || instruction == "l"){
        list();
    }
    else if(instruction == "load"){
        load(args);
    }
    else if(instruction == "run" || instruction == "r"){
        run();
    }
    else if(instruction == "vmmap" || instruction == "m"){
        vmmap();
    }
    else if(instruction == "set" || instruction == "s"){
        setreg(args);
    }
    else if(instruction == "si"){
        step_ins();
    }
    else if(instruction == "start"){
        start();
    }
    else{
        err_msg(ERR_MSG_UNKNOWN_INSTRUCTION);
    }
}

bool SDebugger::set_breakpoint(const std::string& address){
    if(SDB_IS_RUNING(state)){
        unsigned long target = hex2ul(address);
        // check target within text section
        if(target <= text_sec_min_addr || target >= text_sec_max_addr){
            err_msg(ERR_MSG_ADDRESS_OUT_OF_TEXT);
            return false;
        }

        // check break point not exsist
        if(__is_breakpoint(target)){
            err_msg(ERR_MSG_BREAKPOINT_EXIST);
            return false;
        }

        // set and save breakpoint
        unsigned long code = __peek_code(target);
        if(__poke_byte_code(target, 0xcc)){
            breakpoints[target] = code;
            breakpoints_addrs.push_back(target);
            return true;
        }
        else{
            err_msg(ERR_MSG_SET_BREAKPOINT_FAILED);
            return false;
        }
    }else{
        err_msg(ERR_MSG_PROGRAM_NOT_RUNNING);
    }
    return false;
}

bool SDebugger::cont(){
    if(SDB_IS_RUNING(state)){
        // check if current instruction is a breakpoint
        regs_t regs;
        __getregs(regs);
        if(__is_breakpoint(regs.rip)){
            // recover instruction
            if(!__unset_breakpoint(regs.rip)){
                err_quit(ERR_MSG_RECOVER_INSTRUCTION_FAILED);
            }
            // step
            ptrace(PTRACE_SINGLESTEP, child_process, 0, 0);
            waitpid(child_process, 0, 0);
            // reset breakpoint
            __set_breakpoint(regs.rip);
        }
        // cont
        ptrace(PTRACE_CONT, child_process, 0, 0);
        waitpid(child_process, &child_status, 0);
        // status check
        if(WIFEXITED(child_status)){ // terminate
            __child_terminate();
        }
        else if(WIFSTOPPED(child_status)){
            __getregs(regs);
            if(__is_breakpoint(regs.rip-1)){ // is a breakpoint
                // breakpoint message
                char str[128]={};
                sprintf(str, SDB_MSG_BREAKPOINT, regs.rip-1);
                err_msg(string(str));
                // back to breakpoint
                regs.rip = regs.rip-1;
                __setregs(regs);
            }
        }
        return true;
    }
    else{
        err_msg(ERR_MSG_PROGRAM_NOT_RUNNING);
        return false;
    }
}

bool SDebugger::delete_breakpoint(const std::string& id){
    if(SDB_IS_RUNING(state)){
        int ind=-1;
        istringstream ss(id);
        ss>>ind;

        if(ind<0 || ind >= (int)breakpoints.size()){
            err_msg(ERR_MSG_INDEX_OUT_OF_RANGE);
        }

        unsigned long addr = breakpoints_addrs[ind];
        if(__unset_breakpoint(addr)){
            breakpoints.erase(addr);
            breakpoints_addrs.erase(breakpoints_addrs.begin()+ind);
        }
        else{
            err_msg(ERR_MSG_DELETE_BREAKPOINT_FAILED);
        }
    }
    else{
        err_msg(ERR_MSG_PROGRAM_NOT_RUNNING);
    }

    return false;
}

void SDebugger::disasm(const std::string& address)const{
    if(SDB_IS_RUNING(state)){
        // check address is given
        string addr_strip = remove_space(address);
        if(addr_strip==""){
            err_msg(ERR_MSG_ADDRESS_NOT_GIVEN);
            return;
        }
        // check address in text section
        unsigned long start_addr = hex2ul(addr_strip);
        if(start_addr < text_sec_min_addr || start_addr >= text_sec_max_addr){
            err_msg(ERR_MSG_ADDRESS_OUT_OF_TEXT);
            return;
        }
        // x86 instruction size: 1~15 bytes
        // 10 instructions => maximum 150 bytes
        int ind = 0; uint8_t buf[152] = {}; // 152(8 * 19) bytes buffer
        unsigned long cur_addr = start_addr, max_addr = min(start_addr + 150, text_sec_max_addr); // read range
        while (cur_addr < max_addr){ // read until max_addr
            unsigned long code = __peek_code(cur_addr);
            for(int i=0; i<8; i++){
                if(__is_breakpoint(cur_addr+i)){
                    unsigned long origin_code = breakpoints.find(cur_addr+i)->second;
                    buf[ind++] = (uint8_t)origin_code&SDB_TEXT_BYTE_MASK;
                }else{
                    buf[ind++] = (uint8_t)code&SDB_TEXT_BYTE_MASK;
                }
                code = code>>8;
            }
            cur_addr += 8;
        }
        // disasm
        cs_insn *ins;
        int count = cs_disasm(cs_handler, (uint8_t*)buf, max_addr-start_addr, start_addr, 0, &ins);
        // print
        if(count > 0){
            for(int i=0; i<min(count, 10); ++i){
                int n_bytes = ins[i].size;
                printf("%lx:", ins[i].address);
                for(int j=0; j<16; ++j){
                    if(j<n_bytes)printf(" %02x", ins[i].bytes[j]);
                    else printf("   ");
                }
                printf("%-7s %s\n", ins[i].mnemonic, ins[i].op_str);
            }
            if(count<10)err_msg(ERR_MSG_ADDRESS_OUT_OF_TEXT);
            cs_free(ins, count);
        }else{
            err_msg(ERR_MSG_DISASM_FAILED);
        }
    }
    else{
        err_msg(ERR_MSG_PROGRAM_NOT_RUNNING);
    }
}

void SDebugger::dump(const std::string& address)const{
    if(SDB_IS_RUNING(state)){
        string addr_strip = remove_space(address);
        if(addr_strip==""){
            err_msg(ERR_MSG_ADDRESS_NOT_GIVEN);
            return;
        }
        else{
            unsigned long cur_addr = hex2ul(addr_strip);
            // print 5 lines
            for(int i=0; i<5; ++i){
                printf("%lx:", cur_addr + i * 16);
                char text[17] = {};
                // each line has 2 code(16 byte)
                for(int j=0; j<2; ++j){
                    unsigned long code = __peek_code(cur_addr + i * 16 + j * 8);
                    for(int k=0; k<8; ++k){
                        unsigned char byte = code & SDB_TEXT_BYTE_MASK;
                        code = code>>8;

                        printf(" %02x", byte);
                        if(isprint(byte))text[j*8+k] = byte;
                        else text[j*8+k] = '.';
                    }
                }
                printf("  |%s|\n", text);
            }
        }
    }
    else{
        err_msg(ERR_MSG_PROGRAM_NOT_RUNNING);
    }
}

void SDebugger::exit(){
    if(SDB_IS_RUNING(state)){
        kill(child_process, 9);
    }
    state |= SDB_STATE_CLOSED;
}

void SDebugger::getreg(const std::string& reg)const{
    if(SDB_IS_RUNING(state)){
        regs_t regs;
        __getregs(regs);
        string reg_l = remove_space(reg);
        to_lower_string(reg_l);

        unsigned long long value;

        if(reg_l=="rax")value = regs.rax;
        else if(reg_l=="rbx")value = regs.rbx;
        else if(reg_l=="rcx")value = regs.rcx;
        else if(reg_l=="rdx")value = regs.rdx;

        else if(reg_l=="r8")value = regs.r8;
        else if(reg_l=="r9")value = regs.r9;
        else if(reg_l=="r10")value = regs.r10;
        else if(reg_l=="r11")value = regs.r11;

        else if(reg_l=="r12")value = regs.r12;
        else if(reg_l=="r13")value = regs.r13;
        else if(reg_l=="r14")value = regs.r14;
        else if(reg_l=="r15")value = regs.r15;

        else if(reg_l=="rdi")value = regs.rdi;
        else if(reg_l=="rsi")value = regs.rsi;
        else if(reg_l=="rbp")value = regs.rbp;
        else if(reg_l=="rsp")value = regs.rsp;

        else if(reg_l=="rip")value = regs.rip;
        else if(reg_l=="flags")value = regs.eflags;

        else{
            err_msg(ERR_MSG_UNKNOWN_REGISTER_NAME);
            return;
        }

        printf(SDB_REGISTER_VALUE, reg_l.c_str(), value, value);
        printf("\n");
    }
    else{
        err_msg(ERR_MSG_PROGRAM_NOT_RUNNING);
    }
}

void SDebugger::getregs()const{
    if(SDB_IS_RUNING(state)){
        regs_t regs;
        __getregs(regs);
        printf("RAX %-16llx    RBX %-16llx    RCX %-16llx    RDX %-16llx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
        printf("R8  %-16llx    R9  %-16llx    R10 %-16llx    R11 %-16llx\n", regs.r8 , regs.r9 , regs.r10, regs.r11);
        printf("R12 %-16llx    R13 %-16llx    R14 %-16llx    R15 %-16llx\n", regs.r12, regs.r13, regs.r14, regs.r15);
        printf("RDI %-16llx    RSI %-16llx    RBP %-16llx    RSP %-16llx\n", regs.rdi, regs.rsi, regs.rbp, regs.rsp);
        printf("RIP %-16llx    FLAGS %016llx\n", regs.rip, regs.eflags);
    }
    else{
        err_msg(ERR_MSG_PROGRAM_NOT_RUNNING);
    }
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

void SDebugger::list()const{
    for(int i=0; i<(int)breakpoints_addrs.size(); i++){
        map<unsigned long, unsigned long>::const_iterator it = breakpoints.find(breakpoints_addrs[i]);
        printf("\t%d:\t%lx\n", i, it->first);
    }
}

bool SDebugger::load(const string& path){
    if(SDB_IS_LOADED(state)){
        char str[512]={};
        sprintf(str, ERR_MSG_LOAD_MULTIPLE_TIMES, program_file.c_str());
        err_msg(str);
        return false;
    }else{
        // open elf
        string path_strip = remove_space(path);
        FILE* fp = fopen(path_strip.c_str(), "r");
        if (fp == NULL){
            char str[512]={};
            sprintf(str, ERR_MSG_OPEN_FAILED, path_strip.c_str());
            err_msg(str);
            return false;
        }
        // check is elf and get type
        char tmp[5]={};
        fread(tmp, 1, 5, fp);
        if(tmp[0] != 0x7F || tmp[1] != 'E' || tmp[2] != 'L' || tmp[3] != 'F'){
            err_msg(ERR_MSG_FILE_IS_NOT_ELF);
            return false;
        }
        elf_cla = tmp[4];
        // read elf header
        fseek(fp, 0, SEEK_SET);
        if(elf_cla==1){ // 32 bits
            fread(&hdr32, 1, sizeof(Elf32_Ehdr), fp);
        }else if(elf_cla==2){ // 64 bits
            fread(&hdr64, 1, sizeof(Elf64_Ehdr), fp);
        }else{
            err_msg(ERR_MSG_UNKNOWN_ELF_CLASS);
            return false;
        }
        // read sections
        if(elf_cla==1){ // 32 bits
            Elf32_Shdr sh_str_hdr32;
            fseek(fp, hdr32.e_shoff + hdr32.e_shstrndx * sizeof(Elf32_Shdr), SEEK_SET);
            fread(&sh_str_hdr32, 1, sizeof(Elf32_Shdr), fp);

            char names[2048] = {};
            fseek(fp, sh_str_hdr32.sh_offset, SEEK_SET);
            fread(names, 1, sh_str_hdr32.sh_size, fp);

            Elf32_Shdr sh_hdr32;
            for(int i=0; i<hdr32.e_shnum; i++){
                fseek(fp, hdr32.e_shoff + i * hdr32.e_shentsize, SEEK_SET);
                fread(&sh_hdr32, 1, hdr32.e_shentsize, fp);
                
                char *name = names + sh_hdr32.sh_name;
                if(strcmp(name, ".text")==0){
                    text_sec_max_addr = hdr32.e_entry + sh_hdr32.sh_size;
                    break;
                }
            }
        }
        else{ // 64 bits
            Elf64_Shdr sh_str_hdr64;
            fseek(fp, hdr64.e_shoff + hdr64.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
            fread(&sh_str_hdr64, 1, sizeof(Elf64_Shdr), fp);

            char names[2048] = {};
            fseek(fp, sh_str_hdr64.sh_offset, SEEK_SET);
            fread(names, 1, sh_str_hdr64.sh_size, fp);

            Elf64_Shdr sh_hdr64;
            for(int i=0; i<hdr64.e_shnum; i++){
                fseek(fp, hdr64.e_shoff + i * hdr64.e_shentsize, SEEK_SET);
                fread(&sh_hdr64, 1, hdr64.e_shentsize, fp);
                
                char *name = names + sh_hdr64.sh_name;
                if(strcmp(name, ".text")==0){
                    text_sec_max_addr = hdr64.e_entry + sh_hdr64.sh_size;
                    break;
                }
            }
        }
        // load
        program_file = path_strip;
        state |= SDB_STATE_PROGRAM_LOADED;
        char str[512]={};
        if(elf_cla==1){
            text_sec_min_addr = (unsigned long)hdr32.e_entry;
            sprintf(str, SDB_MSG_LOAD, program_file.c_str(), (unsigned long long)hdr32.e_entry);
        }else{
            text_sec_min_addr = (unsigned long)hdr64.e_entry;
            sprintf(str, SDB_MSG_LOAD, program_file.c_str(), (unsigned long long)hdr64.e_entry);
        }
        err_msg(string(str));
        fclose(fp);
        __init_disasm();
        return true;
    }
}

bool SDebugger::run(){
    if(SDB_IS_LOADED(state)){
        if(SDB_IS_RUNING(state)){
            char str[512]={};
            sprintf(str, WARNING_MSG_ALREADY_RUNNING, program_file.c_str());
            err_msg(str);
            cont();
        }
        else{
            start();
            cont();
        }
        return true;
    }
    else{
        err_msg(ERR_MSG_PROGRAM_NOT_LOADED);
        return false;
    }
}

void SDebugger::vmmap()const{
    if(!SDB_IS_RUNING(state)){
        err_msg(ERR_MSG_PROGRAM_NOT_RUNNING);
    }
    else{
        char maps[64]={};
        sprintf(maps, "/proc/%d/maps", child_process);
        ifstream fs = ifstream(maps);
        string str;
        while (fs.peek()!=EOF)
        {
            getline(fs, str);
            istringstream ss = istringstream(str);

            std::string seg, flags, pgoff, dev;
            ino_t inode;
            std::string file_name;

            ss >> seg >> flags >> pgoff >> dev >> inode >> file_name;

            unsigned long from, to;
            sscanf(seg.c_str(), "%lx-%lx", &from, &to);
            printf("%016lx-%016lx\t%s\t%s\n", from, to, flags.substr(0, 3).c_str(), file_name.c_str());
        }
    }
}

bool SDebugger::setreg(const std::string& args){
    if(SDB_IS_RUNING(state)){
        string reg, hex_str;
        istringstream ss(args);
        ss>>reg>>hex_str;

        to_lower_string(reg);
        unsigned long value = hex2ul(hex_str);

        regs_t regs;
        __getregs(regs);

        if(reg=="rax")regs.rax = value;
        else if(reg=="rbx")regs.rbx = value;
        else if(reg=="rcx")regs.rcx = value;
        else if(reg=="rdx")regs.rdx = value;

        else if(reg=="r8")regs.r8 = value;
        else if(reg=="r9")regs.r9 = value;
        else if(reg=="r10")regs.r10 = value;
        else if(reg=="r11")regs.r11 = value;

        else if(reg=="r12")regs.r12 = value;
        else if(reg=="r13")regs.r13 = value;
        else if(reg=="r14")regs.r14 = value;
        else if(reg=="r15")regs.r15 = value;

        else if(reg=="rdi")regs.rdi = value;
        else if(reg=="rsi")regs.rsi = value;
        else if(reg=="rbp")regs.rbp = value;
        else if(reg=="rsp")regs.rsp = value;

        else if(reg=="rip")regs.rip = value;
        else if(reg=="flags")regs.eflags = value;

        else{
            err_msg(ERR_MSG_UNKNOWN_REGISTER_NAME);
            return false;
        }

        __setregs(regs);
        return true;
    }
    else{
        err_msg(ERR_MSG_PROGRAM_NOT_RUNNING);
    }
    return false;
}

bool SDebugger::step_ins(){
    if(SDB_IS_RUNING(state)){
        // record rip
        regs_t regs;
        __getregs(regs);
        // check if current is a breakpoint
        if(__is_breakpoint(regs.rip)){
            // recover instruction
            if(!__unset_breakpoint(regs.rip)){
                err_quit(ERR_MSG_RECOVER_INSTRUCTION_FAILED);
            }
        }
        // step
        ptrace(PTRACE_SINGLESTEP, child_process, 0, 0);
        waitpid(child_process, &child_status, 0);
        // recover breakpoint if it is
        if(__is_breakpoint(regs.rip)) __set_breakpoint(regs.rip);
        // handle child status
        if(WIFEXITED(child_status)){ // terminate
            __child_terminate();
        }else{
            __getregs(regs);
            if(__is_breakpoint(regs.rip)){ // is a breakpoint
                // show breakpoint message
                char str[128]={};
                sprintf(str, SDB_MSG_BREAKPOINT, regs.rip);
                err_msg(string(str));
            }
        }
        
        return true;
    }
    else{
        err_msg(ERR_MSG_PROGRAM_NOT_RUNNING);
        return false;
    }
}

bool SDebugger::start(){
    if(!SDB_IS_LOADED(state)){
        err_msg(ERR_MSG_PROGRAM_NOT_LOADED);
        return false;
    }
    else if(SDB_IS_RUNING(state)){
        char str[128]={};
        sprintf(str, WARNING_MSG_ALREADY_RUNNING, program_file.c_str());
        err_msg(str);
        return false;
    }
    else if(SDB_IS_LOADED(state)){
        pid_t pid = fork();
        if(pid < 0){ // fork failed
            err_msg(ERR_MSG_FORK_FAILED);
            return false;
        }
        else if(pid==0){ // child
            if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)err_quit("ptrace");
            if(execl(program_file.c_str(), "", nullptr))err_quit("execl");
        }else{
            child_process = pid;
            
            int status;
            if(waitpid(child_process, &status, 0)<0){
                err_msg(ERR_MSG_CHILD_PROCESS_INIT_FAILED);
                return false;
            }
            if(WIFSTOPPED(status)){
                ptrace(PTRACE_SETOPTIONS, child_process, 0, PTRACE_O_EXITKILL);
                state |= SDB_STATE_PROCESS_RUNNING;
                char str[512]={};
                sprintf(str, "pid %d", child_process);
                err_msg(string(str));
                if(breakpoints.size()>0){ // when resatrt, might have some breakpoint
                    __setup_all_breakpoint();
                }
                return true;
            }
            else{
                err_msg(ERR_MSG_UNKNOWN);
                return false;
            }
        }
    }
    return false;
}

/**
  USAGE:
    Get all registers.
  WARNING: 
    This function DOES NOT check the child state, make sure child process is running.
**/
void SDebugger::__getregs(regs_t& regs)const{
    if(ptrace(PTRACE_GETREGS, child_process, 0, &regs)!=0){
        err_quit("PTRACE_GETREGS"); // fatal error
    }
}

/**
  USAGE:
    Set all registers.
  WARNING: 
    This function DOES NOT check the child state, make sure child process is running.
**/
void SDebugger::__setregs(const regs_t& regs){
    if(ptrace(PTRACE_SETREGS, child_process, 0, &regs)!=0){
        err_quit("PTRACE_SETREGS"); // fatal error
    }
}

/**
  USAGE:
    Get address text.
  WARNING: 
    This function DOES NOT check the child state, make sure child process is running.
**/
unsigned long SDebugger::__peek_code(unsigned long addr)const{
    unsigned long code = ptrace(PTRACE_PEEKTEXT, child_process, addr, 0);
    return code;
}

/**
  USAGE:
    Set address "byte" code.
  WARNING: 
    This function DOES NOT check the child state, make sure child process is running.
**/
bool  SDebugger::__poke_byte_code(unsigned long addr, unsigned long code){
    unsigned long origin_code = __peek_code(addr);
    return ptrace(PTRACE_POKETEXT, child_process, addr, (origin_code&~SDB_TEXT_BYTE_MASK)|(code&SDB_TEXT_BYTE_MASK))==0;
}

/**
  USAGE:
    Check if address is a breakpoint.
  WARNING: 
    This function DOES NOT check the child state, make sure child process is running.
**/
bool SDebugger::__is_breakpoint(unsigned long addr)const{
    return breakpoints.find(addr) != breakpoints.end();
}

/**
  USAGE:
    Make address to 0xCC, when failed return false.
  WARNING: 
    This function DOES NOT check the child state, make sure child process is running.
**/
bool SDebugger::__set_breakpoint(unsigned long addr){
    if(__is_breakpoint(addr)){
        return __poke_byte_code(addr, 0xcc);
    }
    return false;
}

/**
  USAGE:
    Recover brekpoint to origin instruction.
  WARNING: 
    This function DOES NOT check the child state, make sure child process is running.
**/
bool SDebugger::__unset_breakpoint(unsigned long addr){
    if(__is_breakpoint(addr)){
        return __poke_byte_code(addr, breakpoints[addr]);
    }
    return false;
}

/**
  USAGE:
    Back to loaded state, show message
**/
void SDebugger::__child_terminate(){
    state &= ~SDB_STATE_PROCESS_RUNNING;
    const int es = WEXITSTATUS(child_status);
    char str[512]={};
    if(es==0){
        sprintf(str, SDB_MSG_NORMAL_TERMINATE, child_process);
    }else{
        sprintf(str, SDB_MSG_ABNORMAL_TERMINATE, child_process, es);
    }
    err_msg(str);
}

bool SDebugger::__init_disasm(){
    // open cs_handler
    if(elf_cla==1){ // 32 bit
        if(cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handler) != CS_ERR_OK)return false;
    }else if(elf_cla==2){  // 64 bit
        if(cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handler) != CS_ERR_OK)return false;
    }else {return false;}
    return true;
}

void SDebugger::__close_disasm(){
    // close cs_handler
    cs_close(&cs_handler);
}

void SDebugger::__setup_all_breakpoint(){
    if(SDB_IS_RUNING(state)){
        for (const auto& b : breakpoints){
            if(!__set_breakpoint(b.first)){
                err_msg(ERR_MSG_SET_BREAKPOINT_FAILED);
            }
        }
    }else{
         err_msg(ERR_MSG_PROGRAM_NOT_RUNNING);
    }
    
}
