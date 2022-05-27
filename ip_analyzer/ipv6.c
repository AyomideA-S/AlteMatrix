/* 
IPv6 Address Analyzer by AyomideA-S (https://github.com/AyomideA-S)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <getopt.h>
#include "../versions.h"
#include "ipv6.h"



// function to format the input in useable format
void format_ip(char *ip, char **ipv6, int* dec, int *zone_index, char **expansion, int *log){
    int trash;
    // attempt to resize or reshape the IPv6 address
    if(log[0] != 8){
        char makespace[44] = "";
        int writer = 0;
        int x = 0;
        for(int i = 0; i < log[2]; i++){
            if(ip[i] != ':'){
                makespace[writer] = ip[i];
                x++;
            } else {
                makespace[writer] = ':';
                x = 0;
            }
            writer++;
        }
        for(int i = log[1]; i > 0; i--){
            makespace[writer++] = '0';
            makespace[writer++] = ':';
        }
        for (int i = log[2] + 1; i < strlen(ip); i++){
            makespace[writer] = ip[i];
            writer++;
        }
        // stores the hexadecimal values of the IPv6 address as they are in the input
        sscanf(makespace, "%x:%x:%x:%x:%x:%x:%x:%x%%%d", &ipv6[0], &ipv6[1], &ipv6[2], &ipv6[3], &ipv6[4], &ipv6[5], &ipv6[6], &ipv6[7], zone_index);
        // stores the decimal values of the IPv6 address as they are in the input
        sscanf(makespace, "%x:%x:%x:%x:%x:%x:%x:%x%%%d", &dec[0], &dec[1], &dec[2], &dec[3], &dec[4], &dec[5], &dec[6], &dec[7], &trash);
    } else{
        // stores the hexadecimal values of the IPv6 address as they are in the input
        sscanf(ip, "%x:%x:%x:%x:%x:%x:%x:%x%%%d", &ipv6[0], &ipv6[1], &ipv6[2], &ipv6[3], &ipv6[4], &ipv6[5], &ipv6[6], &ipv6[7], zone_index);
        // stores the decimal values of the IPv6 address as they are in the input
        sscanf(ip, "%x:%x:%x:%x:%x:%x:%x:%x%%%d", &dec[0], &dec[1], &dec[2], &dec[3], &dec[4], &dec[5], &dec[6], &dec[7], &trash);
    }

    // expands the IPv6 address and stores it in expansion
    for(int i=0; i<8; i++){
        char digits[5];
        process(ipv6[i], digits);
        expansion[i] = malloc(strlen(digits) + 1);
        strcpy(expansion[i], digits);
    }
}



int main(int argc, char *argv[]){
    // // for debugging purposes
    // for (int i = 0; i < argc; i++){
    //     printf("argv[%d]: %s\n", i, argv[i]);
    // }

    FILE *file = NULL;

    char *ip = NULL;
    char *ipv6[8];
    unsigned int dec[8];
    char** expansion = malloc(8 * sizeof(char *));
    int zone_index = -1;
    int* ptr = &zone_index;
    int cidr = -1;

    char file_name[256];
    int file_flag = 0;
    int execute_flag = 0;
    int analyze_flag = 0;

    // if no arguments are given, print usage and exit
    if(argc == 1){
        fprintf(stdout, "\nIPv6 Address Analyzer by Ayomide A-S (https://github.com/AyomideA-S)\n");
        fprintf(stdout, "AlteMatrix %s [Version %s %s]\n\n", IPv6.name, IPv6.version, IPv6.development_stage);
        print_usage(stdout, argv[0]);
    }
    // if the user has given arguments, process them
    else{
        if(argv[1][0] == '-'){
            parse_args(argc, argv, ip, &cidr, file_name, &analyze_flag, &execute_flag, &file_flag);
        } else {
        // stores the IPv6 address as it is in the input
        ip = malloc(strlen(argv[1]) + 1);
        strcpy(ip, argv[1]);
        optind++;
        }
    }

    parse_args(argc, argv, ip, &cidr, file_name, &analyze_flag, &execute_flag, &file_flag);

    // checks for a valid filename
    if(file_flag == 1) {
        file = fopen(file_name, "w");

        if(!file){
            fprintf(stderr, "Error: File could not be created!");
            exit(EXIT_FAILURE);
        }
    } else {file = stdout;}

    // execution starts here
    format_ip(ip, ipv6, dec, ptr, expansion, count_octets(ip));

    switch(validate_input(ip, ipv6, dec, zone_index, cidr)) {
        case BAD_IP_FORMAT:
            fprintf(stderr, "Error: Wrong IPv6 format provided!");
            exit(EXIT_FAILURE);
        case BAD_IP_ADDRESS:
            fprintf(stderr, "Error: Invalid IPV6 address provided!");
            exit(EXIT_FAILURE);
        case BAD_IP_ZONE:
            fprintf(stderr, "Error: Invalid zone index provided!");
            exit(EXIT_FAILURE);
        case BAD_CIDR:
            fprintf(stderr, "Error: Invalid CIDR mask provided!");
            exit(EXIT_FAILURE);
    }

    switch(execute_flag){
        case ABBREVIATE_IPV6_ADDRESSES:
            shrink(ipv6, dec);
            break;
        case EXPAND_IPV6_ADDRESSES:
            expand(expansion);
            break;
        default:
            expand(expansion);
            break;
    }

    if(analyze_flag == 1){
        if(cidr == -1)
            cidr = 0;
        analyze(file, ip, ipv6, expansion, zone_index, cidr);
    }

    if(file)
        fclose(file);

    exit(EXIT_SUCCESS);
}
