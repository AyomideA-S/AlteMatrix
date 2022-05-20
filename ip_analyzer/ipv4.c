/* 
IPv4 Address Analyzer by AyomideA-S (https://github.com/AyomideA-S)
NOTE: This code includes knowledge acquired from David Bombal's "Ethical Hacking for Beginners" course on Udemy!
You can access the course at: 
https://www.udemy.com/course/pratcical-ethical-hacking-for-beginners/?src=sac&kw=Ethical+hacking+for+beginner
*/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <getopt.h>
#include "../versions.h"
#include "ip.h"



// function to format the input in useable format
void format_ip(char *ip, int *ipv4) {
    sscanf(ip, "%d.%d.%d.%d", &ipv4[0], &ipv4[1], &ipv4[2], &ipv4[3]);
}
// function to format the input in useable format
void format_subnet(char* subnet, int *subnets) {
    sscanf(subnet, "%d.%d.%d.%d", &subnets[0], &subnets[1], &subnets[2], &subnets[3]);
}



int main(int argc, char *argv[]) {
    // for debugging purposes
    // for (int i = 0; i < argc; i++){
    //     printf("argv[%d]: %s\n", i, argv[i]);
    // }

    char* ip = "";
    char* subnet = "";
    int ipv4[4] = {-1, -1, -1, -1}, subnets[4] = {-1, -1, -1, -1};
    int zero = 4;
    int mask = 0;
    int focal;

    int opt;

    struct option longopts[] = {
        { "help", no_argument, NULL, 'h' },
        { "ip", required_argument, NULL, 'i' },
        { "subnet", required_argument, NULL, 's' },
        { "mask", required_argument, NULL, 'm' },
        { "file", optional_argument, NULL, 'f' },
        { "version", no_argument, NULL, 'V' },
        { 0, 0, NULL, 0 }
    };

    while((opt = getopt_long(argc, argv, "hi:s:m:f::V", longopts, 0)) != -1 ){
        switch(opt){
        case 'h':
            print_usage(stdout, argv[0]);
            exit(EXIT_SUCCESS);
        case 'i':
            ip = optarg;
            break;
        case 's':
            subnet = optarg;
            break;
        case 'm':
            mask = atoi(optarg);
            break;
        case 'f':
            break;
        case 'V':
            printf("AlteMatrix %s [Version %s %s]\n", IPv4.name, IPv4.version, IPv4.state);
            exit(EXIT_SUCCESS);
        default:
            fprintf(stderr, "Usage: %s  [-h|--help] -i|--ip <IPv4_address> [-s|--subnet <subnet>] [-m|--mask <mask>] [-f|--file <filepath>] [-V|--version]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // for debugging purposes
    // printf("argc=%d optind=%d\n", argc, optind);

    if (optind < argc) {
        fprintf(stderr, "Expected argument after options\n");
        exit(EXIT_FAILURE);
    }

    // for debugging purposes
    // argc -= optind;
    // argv += optind; 

    format_ip(ip, ipv4);
    if(subnet != "")
        format_subnet(subnet, subnets);
    int flag = validate_input(ipv4, subnet, subnets, mask);

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
            fprintf(stderr, "Error: Invalid subnet mask provided!");
            exit(EXIT_FAILURE);
    }

    present_ip(ip, ipv4);
    if(subnet != "")
        zero = present_subnet(subnet, subnets);
    if(mask)
        present_mask(mask);
    focal = summarize(ip, ipv4, subnets, zero);
    if(subnet != "")
        yes_subnet(subnet, focal);
    if(mask)
        yes_mask(mask);

    exit(EXIT_SUCCESS);
}
