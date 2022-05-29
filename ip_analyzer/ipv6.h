/* 
IPv6 Address Analyzer by AyomideA-S (https://github.com/AyomideA-S)
*/

#define ABBREVIATE_IPV6_ADDRESSES 1
#define EXPAND_IPV6_ADDRESSES 2

#define BAD_IP_ADDRESS -1
#define BAD_IP_FORMAT -2
#define BAD_IP_ZONE -3
#define BAD_CIDR -4

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <getopt.h>

#ifdef PROGRAM_NAME
#undef PROGRAM_NAME
#define PROGRAM_NAME "IPv6"
#endif
#ifdef PROGRAM_VERSION
#undef PROGRAM_VERSION
#define PROGRAM_VERSION "0.1.0"
#endif
#ifdef PROGRAM_DEVELOPMENT_STAGE
#undef PROGRAM_DEVELOPMENT_STAGE
#define PROGRAM_DEVELOPMENT_STAGE "beta"
#endif



// print help
void print_usage_ipv6 (FILE* stream, char *program_path){
    const char *program_name = strrchr(program_path, '/');
    program_name = program_name ? program_name + 1 : program_path;
    fprintf(stream, "Usage:  %s <IPv6_address> [OPTIONS]\n", program_name);
    fprintf(stream,
            "  -h  --help\t\t\t" "Display this usage information and exit.\n"
            "  -a  --abbr\t\t\t" "Abbreviates IPv6 address.\n"
            "  -e  --expand\t\t\t" "Expands IPv6 address.\n"
            "  -c  --cidr\t\t\t" "Takes IPv6 CIDR mask.\n"
            "  -v  --verbose\t\t\t" "Prints out a detailed analysis of the IPv6 address.\n"
            "  -f  --file=[FILENAME]\t\t" "Write all output to a file (defaults to ipanalysis.txt).\n"
            "  -V  --version\t\t\t"
            "Display the program version.\n");
    exit(EXIT_SUCCESS);
}

// function to parse the input and possible argument flags
void parse_args_ipv6(int argc, char *argv[], char *ip, int *cidr, char *file_name, int *analyze_flag, int *execute_flag, int *file_flag){
    int opt;
    // struct to define argument flags
    struct option longopts[] = {
        { "help", no_argument, NULL, 'h' },
        { "version", no_argument, NULL, 'V' },
        { "cidr", required_argument, NULL, 'c' },
        { "abbr", no_argument, NULL, 'a' },
        { "expand", no_argument, NULL, 'e' },
        { "verbose", no_argument, NULL, 'v' },
        { "file", optional_argument, NULL, 'f' },
        { 0, 0, NULL, 0 }
    };

    // argument parsing
    while((opt = getopt_long(argc, argv, "hVc:aevf::", longopts, 0)) != -1 ){
        switch(opt){
        case 'h':
            print_usage_ipv6(stdout, argv[0]);
            exit(EXIT_SUCCESS);
        case 'V':
            printf("AlteMatrix %s [Version %s %s]\n", PROGRAM_NAME, PROGRAM_VERSION, PROGRAM_DEVELOPMENT_STAGE);
            exit(EXIT_SUCCESS);
        case 'c':
            *cidr = atoi(optarg);
            break;
        case 'a':
            *execute_flag = 1;
            break;
        case 'e':
            *execute_flag = 2;
            break;
        case 'v':
            *analyze_flag = 1;
            break;
        case 'f':
            strncpy(file_name, (optarg) ? optarg : "ipanalysis.txt", sizeof (file_name));
            file_name[sizeof(file_name) - 1] = '\0';
            *file_flag = 1;
            break;
        default:
            fprintf(stderr, "Usage:  %s <IPv6_address> [-a|--abbr || -e|--expand] [-v|--verbose] [-f\"<filepath>\"|--file=<filepath>] [-h|--help] [-V|--version]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // // for debugging purposes
    // printf("argc=%d optind=%d\n", argc, optind);

    if (optind < argc) {
        fprintf(stderr, "Expected argument after options\n");
        exit(EXIT_FAILURE);
    }
}

// function to count the number of octets present in given IPv6 address
int *count_octets(char *ip){
    int missing_index = 0;
    int count = 0;
    for(int i=0; i<strlen(ip); i++){
        if(ip[i] == ':'){
            count++;
            if(ip[i + 1] == ':'){
                missing_index = i;
            }
        }
    }
    int missing = 8 - count;
    int* log = (int *)malloc(3 * sizeof(int));
    log[0] = count; 
    log[1] = missing;
    log[2] = missing_index + 1;
    return log;
}

// function to expand the IPv6 address
void process(char* hex, char* digits){
    sprintf(digits, "%x", hex);
    int len = strlen(digits);
    
    if(len < 4){
        int diff = 4 - len;
        int x = 3;
        for(int i = len; i >= 0; i--){
            digits[x] = digits[x - diff];
            x--;
        }

        for(int i = 0; i < 4 - len; i++)
            digits[i] = '0';
    }
}

// function to format the input in useable format
void format_ipv6(char *ip, char **ipv6, int* dec, int *zone_index, char **expansion, int *log){
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

// function to validate the IPv6 address
int validate_ipv6(char *ip, char **ipv6, int* dec, int zone_index, int cidr){
    int count = 0;
    
    for(int i=0; i<strlen(ip); i++){
        if(ip[i] == ':'){
            count++;
        } else {
            count = 0;
        }

        if(count > 2){
            return BAD_IP_FORMAT;
        }
    }

    for (int i = 0; i < 8; i++){
        if(dec[i] > 65535 || dec[i] < 0){
            return BAD_IP_ADDRESS;
        }
    }

    if(zone_index != -1){
        if(zone_index > 255 || zone_index < 0){
            return BAD_IP_ZONE;
        }
    }

    if(cidr != -1){
        if(cidr > 64 || cidr < 0){
            return BAD_CIDR;
        }
    }
    
    return 0;
}

// function to print the IPv6 address
void expand(char** expansion){
    for(int i = 0; i < 7; i++){
        printf("%s:", expansion[i]);
    } printf("%s\n", expansion[7]);
}

// function to shorten the IPv6 address
void shrink(char** IPv6, int* dec){
    int index = 0;
    int streak = 0;
    int longest_streak = 0;
    int trash;

    for(int i = 0; i < 8; i++){
        if(dec[i] == 0){
            streak++;
            if(streak > longest_streak){
                longest_streak = streak;
                index = i;
            }
        } else {
            streak = 0;
        }
    }

    index += 1 - longest_streak;
    
    for(int i = 0; i < 8; i++){
        if(i == index){
            i += longest_streak - 1;
            putchar(':');
        } else if(i == 7){
            printf("%x", IPv6[7]);
        } else {
            printf("%x:", IPv6[i]);
        }
    } putchar('\n');
}

// function to analyze the IPv6 address
void analyze(FILE* stream, char* ip, char** ipv6, char** expansion, int zone_index, int cidr){
    fprintf(stream, "IP address: %s\n", ip);

    fprintf(stream, "\nThis is a %d-bit address block.\n", cidr);
    fprintf(stream, "CIDR: ");
    for(int i = 0; i < 4; i++){
        fprintf(stream, "%x:", ipv6[i]);
    } fprintf(stream, ":/%d\n", cidr);
    
    fprintf(stream, "Expanded CIDR: ");
    for(int i = 0; i < 4; i++){
        fprintf(stream, "%s:", expansion[i]);
    } fprintf(stream, "0000:0000:0000:0000/%d\n", cidr);

    fprintf(stream, "IP Range: ");

    for(int i = 0; i < 4; i++){
        fprintf(stream, "%s:", expansion[i]);
    } fprintf(stream, "0000:0000:0000:0000 - ");

    for(int i = 0; i < 4; i++){
        fprintf(stream, "%s:", expansion[i]);
    } fprintf(stream, "ffff:ffff:ffff:ffff\n");

    fprintf(stream, "Scope ID/Zone ID: %d\n", zone_index);

    int hosts = 64 - cidr;
    int supported_hosts = pow(2, hosts);
    fprintf(stream, "Number of supported Hosts: %d\n", supported_hosts);
    long double total = pow(2, 64) * pow(2, (double)hosts);
    fprintf(stream, "Number of addresses: %.0Lf\n", total);
}



// main program function
int ipv6(int argc, char *argv[]){
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
    if(argc == 2){
        fprintf(stdout, "\nIPv6 Address Analyzer by Ayomide A-S (https://github.com/AyomideA-S)\n");
        fprintf(stdout, "AlteMatrix %s [Version %s %s]\n\n", PROGRAM_NAME, PROGRAM_VERSION, PROGRAM_DEVELOPMENT_STAGE);
        print_usage_ipv6(stdout, argv[0]);
    }
    // if the user has given arguments, process them
    else{
        if(argv[2][0] == '-'){
            parse_args_ipv6(argc, argv, ip, &cidr, file_name, &analyze_flag, &execute_flag, &file_flag);
        } else {
            // stores the IPv6 address as it is in the input
            ip = malloc(strlen(argv[1]) + 1);
            strcpy(ip, argv[1]);
            optind++;
        }
    }

    parse_args_ipv6(argc, argv, ip, &cidr, file_name, &analyze_flag, &execute_flag, &file_flag);

    // checks for a valid filename
    if(file_flag == 1) {
        file = fopen(file_name, "w");

        if(!file){
            fprintf(stderr, "Error: File could not be created!");
            exit(EXIT_FAILURE);
        }
    } else {file = stdout;}

    // execution starts here
    format_ipv6(ip, ipv6, dec, ptr, expansion, count_octets(ip));

    switch(validate_ipv6(ip, ipv6, dec, zone_index, cidr)) {
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
