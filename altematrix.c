#include <stdio.h>
#include <stdlib.h>

#define PROGRAM_NAME "AlteMatrix"
#define PROGRAM_VERSION "0.1.0"
#define PROGRAM_DEVELOPMENT_STAGE "beta"

#include "ip_analyzer/ipv4.h"
#include "ip_analyzer/ipv6.h"
#include "modules.h"



int main(int argc, char *argv[]){
    // for debugging purposes
    // for (int i = 0; i < argc; i++){
    //     printf("argv[%d]: %s\n", i, argv[i]);
    // }

    // if no arguments are given, print usage and exit
    if(argc == 1){
        fprintf(stdout, "\nAlteMatrix by Ayomide A-S (https://github.com/AyomideA-S)\n");
        fprintf(stdout, "AlteMatrix [Version %s %s]\n\n", PROGRAM_VERSION, PROGRAM_DEVELOPMENT_STAGE);
        print_usage(stdout, argv[0]);
    }
    // if the user has given arguments, process them
    else{
        if(argv[1][0] == '-'){
            parse_args(argc, argv);
        } else {
            // checks for selected module
            if(!strcmp(argv[1], "ipv4"))
                ipv4(argc, argv);
            else if(!strcmp(argv[1], "ipv6"))
                ipv6(argc, argv);
            else
                fprintf(stderr, "Invalid command: %s\n", argv[1]);
                print_usage(stdout, argv[0]);
            optind++;
        }
    }

    exit(EXIT_SUCCESS);
}