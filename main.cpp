// c lib
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// c++ lib
#include <vector>
#include <string>
#include <fstream>

using namespace std;

// constant
#define STATE_INIT              0x00000000
#define STATE_PROGRAM_LOADED    0x00000001
#define STATE_HAVE_SCRIPT       0x00000002
#define STATE_PROCESS_RUNNING   0x00000004

// type
typedef int state_t;

// global variable
state_t state = STATE_INIT;
vector<string> script(0);

// function prototype
void pars_arg(int argc, char *argv[]);      // parsing argument
string read_cmd();                          // read cmd from script/stdin
void exec_cmd(const string& cmd);           // exec cmd

//
int main(int argc, char *argv[])
{
    pars_arg(argc, argv);

    while (true)
    {
        string cmd = read_cmd();
        exec_cmd(cmd);
    }
}

// function body
void pars_arg(int argc, char *argv[])
{
    int opt;

    // read option
    while ((opt = getopt(argc, argv, "s:")) != -1)
    {
        switch (opt)
        {
        case 's':
        {
            state |= STATE_HAVE_SCRIPT;

            // read script
            string str;
            ifstream script_file(optarg);

            while (getline(script_file, str))
            {
                script.push_back(str);
            }

            break;
        }
        default: /* ? */
        {
            fprintf(stderr, "Usage: %s [-s script] [program]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
        }
    }
    // read argument
    if (optind >= argc)
    {
        /* no program specify */
    }
    else
    {
        // load program
        if (true){ // gdb::load(argv[optind])
            state |= STATE_PROGRAM_LOADED;
            printf("%s loaded\n", argv[optind]);
        }
    }
}
