/* 
IPv6 Address Analyzer by AyomideA-S (https://github.com/AyomideA-S)
*/

#define ABBREVIATE_IPV6_ADDRESSES 1
#define EXPAND_IPV6_ADDRESSES 2

#define BAD_IP_ADDRESS -1
#define BAD_IP_FORMAT -2
#define BAD_IP_ZONE -3
#define BAD_CIDR -4

#include <math.h>

// print help
void print_usage (FILE* stream, char *program_path){
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
void parse_args(int argc, char *argv[], char *ip, int *cidr, char *file_name, int *analyze_flag, int *execute_flag, int *file_flag){
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
            print_usage(stdout, argv[0]);
            exit(EXIT_SUCCESS);
        case 'V':
            printf("AlteMatrix %s [Version %s %s]\n", IPv6.name, IPv6.version, IPv6.development_stage);
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
    int* log = malloc(3 * sizeof(int));
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

// function to validate the IPv6 address
int validate_input(char *ip, char **ipv6, int* dec, int zone_index, int cidr){
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
