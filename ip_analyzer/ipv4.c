/* 
IPv4 Address Analyzer by AyomideA-S (https://github.com/AyomideA-S)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <getopt.h>
#include "../versions.h"
#include "ipv4.h"



// function to format the input in useable format
void format_ip(char *ip, int *ipv4){
    sscanf(ip, "%d.%d.%d.%d", &ipv4[0], &ipv4[1], &ipv4[2], &ipv4[3]);
}
// function to format the input in useable format
void format_subnet(char* subnet, int *subnets){
    sscanf(subnet, "%d.%d.%d.%d", &subnets[0], &subnets[1], &subnets[2], &subnets[3]);
}



int main(int argc, char *argv[]){
    // for debugging purposes
    // for (int i = 0; i < argc; i++){
    //     printf("argv[%d]: %s\n", i, argv[i]);
    // }
    FILE *file = NULL;

    char* ip = "";
    char* subnet = "";
    int ipv4[4] = {-1, -1, -1, -1}, subnets[4] = {-1, -1, -1, -1};
    int zero = 4;
    int cidr = -1;
    int focal;

    char filename[256];
    int file_flag = 0;
    int opt;

    // struct for argument flags
    struct option longopts[] = {
        { "help", no_argument, NULL, 'h' },
        { "version", no_argument, NULL, 'V' },
        { "ip", required_argument, NULL, 'i' },
        { "subnet", required_argument, NULL, 's' },
        { "cidr", required_argument, NULL, 'c' },
        { "file", optional_argument, NULL, 'f' },
        { 0, 0, NULL, 0 }
    };

    // parsing arguments and options/flags
    while((opt = getopt_long(argc, argv, "hVi:s:c:f::", longopts, 0)) != -1 ){
        switch(opt){
        case 'h':
            print_usage(stdout, argv[0]);
            exit(EXIT_SUCCESS);
        case 'V':
            printf("AlteMatrix %s [Version %s %s]\n", IPv4.name, IPv4.version, IPv4.development_stage);
            exit(EXIT_SUCCESS);
        case 'i':
            ip = optarg;
            break;
        case 's':
            subnet = optarg;
            break;
        case 'c':
            cidr = atoi(optarg);
            break;
        case 'f':
            strncpy(filename, (optarg) ? optarg : "ipanalysis.txt", sizeof (filename));
            filename[sizeof(filename) - 1] = '\0';
            file_flag = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s  -i|--ip <IPv4_address> [-s|--subnet <subnet_mask>] [-c|--cidr <CIDR_mask>] [-f\"<filepath>\"|--file=<filepath>] [-h|--help] [-V|--version]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // for debugging purposes
    // printf("argc=%d optind=%d\n", argc, optind);

    if (optind < argc) {
        fprintf(stderr, "Expected argument after options\n");
        exit(EXIT_FAILURE);
    }

    format_ip(ip, ipv4);
    if(subnet != "")
        format_subnet(subnet, subnets);
    int flag = validate_input(ipv4, subnet, subnets, cidr);

    switch(flag) {
        case 1:
            fprintf(stderr, "Error: Wrong IPv4 format provided!");
            exit(EXIT_FAILURE);
        case 10:
            fprintf(stderr, "Error: Wrong subnet format provided!");
            exit(EXIT_FAILURE);
        case 11:
            fprintf(stderr, "Error: Invalid IPV4 address provided!");
            exit(EXIT_FAILURE);
        case 100:
            fprintf(stderr, "Error: Invalid subnet address provided!");
            exit(EXIT_FAILURE);
        case 3:
            fprintf(stderr, "Error: Invalid CIDR mask provided!");
            exit(EXIT_FAILURE);
    }

    if(file_flag == 1) {
        file = fopen(filename, "w");

        if(!file){
            fprintf(stderr, "Error: File could not be created!");
            exit(EXIT_FAILURE);
        }
    } else {file = stdout;}
    
        

    present_ip(ip, ipv4, subnets, file);
    if(subnet != "")
        zero = present_subnet(subnet, subnets, file);
    if(cidr != -1)
        present_cidr(cidr, file);
    focal = summarize(ip, ipv4, subnets, zero, file);
    if(subnet != "")
        yes_subnet(subnet, focal, file);
    if(cidr != -1)
        yes_cidr(cidr, file);

    if(file)
        fclose(file);

    exit(EXIT_SUCCESS);
}
