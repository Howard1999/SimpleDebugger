// c lib
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// c++ lib
#include <iostream>

using namespace std;

// my lib
#include "sdb.hpp"

// global variable
sdb::SDebugger debugger;

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
            debugger.assign_script(optarg);
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
        debugger.load(argv[optind]);
    }
}

// main
int main(int argc, char *argv[])
{
    pars_arg(argc, argv);

    while (!debugger.is_closed())
    {
        debugger.fetch_command();
        debugger.exec_command();
    }
    
    return 0;
}
