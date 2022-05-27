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

    char* ip = NULL;
    char* subnet = "";
    int ipv4[4] = {-1, -1, -1, -1}, subnets[4] = {-1, -1, -1, -1};
    int zero = 4;
    int cidr = -1;
    int focal;

    char filename[256];
    int file_flag = 0;

    // if no arguments are given, print usage and exit
    if(argc == 1){
        fprintf(stdout, "\nIPv6 Address Analyzer by Ayomide A-S (https://github.com/AyomideA-S)\n");
        fprintf(stdout, "AlteMatrix %s [Version %s %s]\n\n", IPv4.name, IPv4.version, IPv4.development_stage);
        print_usage(stdout, argv[0]);
    }
    // if the user has given arguments, process them
    else{
        if(argv[1][0] == '-'){
                parse_args(argc, argv, ip, subnet, &cidr, filename, &file_flag);
        } else {
        // stores the IPv4 address as it is in the input
        ip = malloc(strlen(argv[1]) + 1);
        strcpy(ip, argv[1]);
        optind++;
        }
    }

    parse_args(argc, argv, ip, subnet, &cidr, filename, &file_flag);

    if(file_flag == 1) {
        file = fopen(filename, "w");

        if(!file){
            fprintf(stderr, "Error: File could not be created!");
            exit(EXIT_FAILURE);
        }
    } else {file = stdout;}

    format_ip(ip, ipv4);
    if(subnet != "")
        format_subnet(subnet, subnets);

    switch(validate_input(ipv4, subnet, subnets, cidr)) {
        case WRONG_IP:
            fprintf(stderr, "Error: Wrong IPv4 format provided!");
            exit(EXIT_FAILURE);
        case WRONG_SUBNET:
            fprintf(stderr, "Error: Wrong subnet format provided!");
            exit(EXIT_FAILURE);
        case INVALID_IP:
            fprintf(stderr, "Error: Invalid IPV4 address provided!");
            exit(EXIT_FAILURE);
        case INVALID_SUBNET:
            fprintf(stderr, "Error: Invalid subnet address provided!");
            exit(EXIT_FAILURE);
        case INVALID_CIDR:
            fprintf(stderr, "Error: Invalid CIDR mask provided!");
            exit(EXIT_FAILURE);
    }

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
