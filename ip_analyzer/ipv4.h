/* 
IPv6 Address Analyzer by AyomideA-S (https://github.com/AyomideA-S)
*/

#define WRONG_IP 1
#define WRONG_SUBNET 2
#define INVALID_IP 3
#define INVALID_SUBNET 4
#define INVALID_CIDR 5

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <getopt.h>

#ifdef PROGRAM_NAME
#undef PROGRAM_NAME
#define PROGRAM_NAME "IPv4"
#endif
#ifdef PROGRAM_VERSION
#undef PROGRAM_VERSION
#define PROGRAM_VERSION "0.1.0"
#endif
#ifdef PROGRAM_DEVELOPMENT_STAGE
#undef PROGRAM_DEVELOPMENT_STAGE
#define PROGRAM_DEVELOPMENT_STAGE "beta"
#endif



int subnet_flag = 0;
int cidr_flag = -1;

// array of subnet masks
char *MASKS[33] = {"0.0.0.0", "128.0.0.0", "192.0.0.0", "224.0.0.0", "240.0.0.0", "248.0.0.0", "252.0.0.0", "254.0.0.0", "255.0.0.0", 
    "255.128.0.0", "255.192.0.0", "255.224.0.0", "255.240.0.0", "255.248.0.0", "255.252.0.0", "255.254.0.0", "255.255.0.0", 
    "255.255.128.0", "255.255.192.0", "255.255.224.0", "255.255.240.0", "255.255.248.0", "255.255.252.0", "255.255.254.0", 
    "255.255.255.0", "255.255.255.128", "255.255.255.192", "255.255.255.224", "255.255.255.240", "255.255.255.248", 
    "255.255.255.252", "255.255.255.254", "255.255.255.255"};

// print help
void print_usage_ipv4 (FILE* stream, char *program_path){
    const char *program_name = strrchr(program_path, '/');
    program_name = program_name ? program_name + 1 : program_path;
    fprintf(stream, "Usage:  %s <IPv4_address> [OPTIONS]\n", program_name);
    fprintf(stream,
            "  -h  --help\t\t\t" "Display this usage information and exit.\n"
            "  -s  --subnet <subnet>\t\t" "Takes IPv4 subnet address.\n"
            "  -c  --cidr <CIDR_mask>\t" "Takes IPv4 CIDR mask.\n"
            "  -f  --file=[FILENAME]\t\t" "Write all output to a file (defaults to ipanalysis.txt).\n"
            "  -V  --version\t\t\t"
            "Display the program version.\n");
    exit(EXIT_SUCCESS);
}

// function to parse the input and possible argument flags
void parse_args_ipv4(int argc, char *argv[], char *ip, char *subnet, int *cidr, char *file_name, int *file_flag){
    int opt;
    // struct to define argument flags
    struct option longopts[] = {
        { "help", no_argument, NULL, 'h' },
        { "version", no_argument, NULL, 'V' },
        { "subnet", required_argument, NULL, 's' },
        { "cidr", required_argument, NULL, 'c' },
        { "file", optional_argument, NULL, 'f' },
        { 0, 0, NULL, 0 }
    };

    // parsing arguments and options/flags
    while((opt = getopt_long(argc, argv, "hVi:s:c:f::", longopts, 0)) != -1 ){
        switch(opt){
        case 'h':
            print_usage_ipv4(stdout, argv[0]);
            exit(EXIT_SUCCESS);
        case 'V':
            printf("AlteMatrix %s [Version %s %s]\n", PROGRAM_NAME, PROGRAM_VERSION, PROGRAM_DEVELOPMENT_STAGE);
            exit(EXIT_SUCCESS);
        case 's':
            subnet = optarg;
            break;
        case 'c':
            *cidr = atoi(optarg);
            break;
        case 'f':
            strncpy(file_name, (optarg) ? optarg : "ipanalysis.txt", sizeof (file_name));
            file_name[sizeof(file_name) - 1] = '\0';
            *file_flag = 1;
            break;
        default:
            fprintf(stderr, "Usage:  %s <IPv4_address> [-s|--subnet <subnet_mask>] [-c|--cidr <CIDR_mask>] [-f\"<filepath>\"|--file=<filepath>] [-h|--help] [-V|--version]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // for debugging purposes
    // printf("argc=%d optind=%d\n", argc, optind);

    if (optind < argc) {
        fprintf(stderr, "Expected argument after options\n");
        exit(EXIT_FAILURE);
    }
}

// function to format the input in useable format
void format_ipv4(char *ip, int *ipv4){
    sscanf(ip, "%d.%d.%d.%d", &ipv4[0], &ipv4[1], &ipv4[2], &ipv4[3]);
}
// function to format the input in useable format
void format_subnet(char* subnet, int *subnets){
    sscanf(subnet, "%d.%d.%d.%d", &subnets[0], &subnets[1], &subnets[2], &subnets[3]);
}

// function to validate user input
int validate_ipv4(int *ipv4, char *subnet, int *subnets, int cidr) {
    for(int i = 0; i < 4; i++) {
        if(ipv4[i] == -1)
            return WRONG_IP;
    }
    for(int i = 0; i < 4; i++) {
        if(ipv4[i] > 255 || ipv4[i] < 0)
            return INVALID_IP;
    }

    if(subnet != ""){
        for(int i = 0; i < 4; i++) {
            if(subnets[i] == -1)
                return WRONG_SUBNET;
        }
        for(int i = 0; i < 4; i++) {
            if(subnets[i] > 255 || subnets[i] < 0)
                return INVALID_SUBNET;
        }
        subnet_flag = 1;
    }
    
    if(cidr != -1){
        if(cidr > 32 || cidr < 0) return INVALID_CIDR;
        cidr_flag = 1;
    }
    return 0;
}

// decimal to binary
int decimal_to_binary(int index, int val, char *BINARY, int zero) {
    for(int i = 0; i < 8; i++){
        BINARY[i] = '0';
    }
    BINARY[9] = '\0';
    int i = 8;
    while(val > 0) {
        i--;
        if(val % 2) BINARY[i] = '1';
        else {
            BINARY[i] = '0';
        }
        val /= 2;
    }

    if(zero == 4) {
        for(int i = 0; i < 8; i++) {
            if(BINARY[i] == '0') {
                return index;
            }
        }
    }
    return zero;
}

// function to get the class of the IPv4 network
char get_class(int *ipv4) {
    if(ipv4[0] < 128) return 'A';
    else if(ipv4[0] < 192) return 'B';
    else if(ipv4[0] < 224) return 'C';
    else if(ipv4[0] < 240) return 'D';
    else return 'E';
}

// function to present the output in predefined format
void present_ip(char* ip, int *ipv4, int* subnets, FILE *stream){
    char BINARY[9] = {0,0,0,0,0,0,0,0,'\0'};

    // plain ipv4 format
    fprintf(stream, "\n %12s IPv4: %s%9s\n|", " ", ip, " ");
    for(int i = 0; i < 43; i++) {
        fprintf(stream, "-");
    }
    fprintf(stream, "|\n");
    for(int i = 1; i <= 4; i++) {
        fprintf(stream, "| Octet %d  ", i);
    }
    fprintf(stream, "|\n");
    for(int i = 0; i < 4; i++) {
        fprintf(stream, "|");
        for(int j = 0; j < 10; j++)
        fprintf(stream, "-");
    }
    fprintf(stream, "|\n");
    for(int i = 0; i < 4; i++) {
        int zero = 0;
        decimal_to_binary(i, ipv4[i], BINARY, zero);
        fprintf(stream, "| %s ", BINARY);
    }
    fprintf(stream, "|\n|");
    for(int i = 0; i < 43; i++) {
        fprintf(stream, "-");
    }
    fprintf(stream, "|\n");
}

// subnet format
int present_subnet(char *subnet, int *subnets, FILE *stream){
    char BINARY[9] = {0,0,0,0,0,0,0,0,'\0'};

    fprintf(stream, "%8s Subnet mask: %s%9s\n", " ", subnet, " ");
    fprintf(stream, "|");
    for(int i = 0; i < 43; i++) {
        fprintf(stream, "-");
    }
    fprintf(stream, "|\n");
    for(int i = 1; i <= 4; i++) {
        fprintf(stream, "| Octet %d  ", i);
    }
    fprintf(stream, "|\n");
    for(int i = 0; i < 4; i++) {
        fprintf(stream, "|");
        for(int j = 0; j < 10; j++)
        fprintf(stream, "-");
    }
    fprintf(stream, "|\n");
    int zero = 4;
    for(int i = 0; i < 4; i++) {
        // index of the first octet with a "0" in the subnets array
        zero = decimal_to_binary(i, subnets[i], BINARY, zero);
        fprintf(stream, "| %s ", BINARY);
    }
    fprintf(stream, "|\n|");
    for(int i = 0; i < 43; i++) {
        fprintf(stream, "-");
    }
    fprintf(stream, "|\n");

    return zero;
}

// CIDR mask
void present_cidr(int cidr, FILE *stream){
    fprintf(stream, "\nThis is a %d-bit address block.\n", cidr);
    int hosts = 32 - cidr;
    fprintf(stream, "Host Bits: %d\n", hosts);
    int supported_hosts = pow(2, hosts) - 2;
    fprintf(stream, "Number of supported Hosts: %d\n", supported_hosts);
    fprintf(stream, "Total IPs: %d\n", supported_hosts+2);
}

// present the summary
int summarize(char* ip, int *ipv4, int *subnets, int zero, FILE *stream){
    char Class;
    char alpha[16];
    char delta[16];
    char gamma[16];
    int focal;
    
    // get the first octet with a "0"
    if(zero != 4) {
        int most_significant_zero = subnets[zero];
        int size = 256 - most_significant_zero;
        fprintf(stream, "Block Size: %d\n", size);
        fprintf(stream, "Subnets: %d\n", 256 / size);
        
        for (int i = 0; i < 257; i += size) {
            if(i > ipv4[zero]) {
                focal = i;
                break;
            }
        }
        
        if(zero == 3) {
            ipv4[zero] = 1;
            sprintf(alpha, "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);

            ipv4[zero] = focal - 1;
            sprintf(delta, "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);

            ipv4[zero] = ipv4[zero] - 1;
            sprintf(gamma, "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
        } else {
            ipv4[3] = 1;
            ipv4[zero] = 0;
            sprintf(alpha, "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);

            ipv4[3] = 255;
            ipv4[zero] = focal - 1;
            sprintf(delta, "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);

            ipv4[3] = ipv4[3] - 1;
            sprintf(gamma, "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
        }
    }
    Class = get_class(ipv4);

    fprintf(stream, "\nSummary\n");
    for(int i = 0; i < 43; i++){
        fprintf(stream, "-");
    }
    if(subnets[0] != -1){
        fprintf(stream, "\nNetwork Address: ");
        for(int i = 0; i < 3; i++) {
            fprintf(stream, "%d.", ipv4[i] & subnets[i]);
        } fprintf(stream, "%d\n", ipv4[3] & subnets[3]);
    } else {
        fprintf(stream, "\nNetwork Address: %s\n", ip);
    }
    
    fprintf(stream, "Class: %c\n", Class);

    if(zero != 4){
        fprintf(stream, "Directed Broadcast Address: %s\n", delta);
        fprintf(stream, "IP Range: %s - %s\n", alpha, gamma);
    }

    return focal;
}

// subnet summary
void yes_subnet(char *subnet, int focal, FILE *stream){
    fprintf(stream, "Subnet Address: %s\n", subnet);
    fprintf(stream, "Wildcard Bits: 0.0.0.%d\n", focal - 1);
    if(cidr_flag == -1){
        int CIDR;
        for(int i=32; i>=0; i--){
            if(strcmp(subnet, MASKS[i]) <= 0)
                CIDR = i;
            else
                break;
        }
        fprintf(stream, "Classless Inter-Domain Routing mask: /%d\n", CIDR);
        fprintf(stream, "Subnet mask: %s\n", MASKS[CIDR - 1]);
    }
}

// CIDR summary
void yes_cidr(int cidr, FILE *stream){
    fprintf(stream, "Classless Inter-Domain Routing mask: /%d\n", cidr);
    fprintf(stream, "Subnet mask: %s\n", MASKS[cidr - 1]);
}



// main program function
int ipv4(int argc, char *argv[]){
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
    if(argc == 2){
        fprintf(stdout, "\nIPv4 Address Analyzer by Ayomide A-S (https://github.com/AyomideA-S)\n");
        fprintf(stdout, "AlteMatrix %s [Version %s %s]\n\n", PROGRAM_NAME, PROGRAM_VERSION, PROGRAM_DEVELOPMENT_STAGE);
        print_usage_ipv4(stdout, argv[0]);
    }
    // if the user has given arguments, process them
    else{
        if(argv[2][0] == '-'){
            parse_args_ipv4(argc, argv, ip, subnet, &cidr, filename, &file_flag);
        } else {
            // stores the IPv4 address as it is in the input
            ip = (char *)malloc(strlen(argv[1]) + 1);
            strcpy(ip, argv[1]);
            optind++;
        }
    }

    parse_args_ipv4(argc, argv, ip, subnet, &cidr, filename, &file_flag);

    if(file_flag == 1) {
        file = fopen(filename, "w");

        if(!file){
            fprintf(stderr, "Error: File could not be created!");
            exit(EXIT_FAILURE);
        }
    } else {file = stdout;}

    format_ipv4(ip, ipv4);
    if(subnet != "")
        format_subnet(subnet, subnets);

    switch(validate_ipv4(ipv4, subnet, subnets, cidr)) {
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
