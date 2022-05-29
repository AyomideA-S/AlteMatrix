#include <string.h>
#include <math.h>
#include <getopt.h>

char IPV4[5] = "ipv4";
char IPV6[5] = "ipv6";



// print help
void print_usage (FILE* stream, char *program_path){
    const char *program_name = strrchr(program_path, '/');
    program_name = program_name ? program_name + 1 : program_path;
    fprintf(stream, "Usage:  %s <command> [OPTIONS]\n", program_name);
    fprintf(stream,
            "Commands:\n"
            "  ipv4\t\t\t\t" "IPv4 address analyzer.\n"
            "  ipv6\t\t\t\t" "IPv6 address analyzer.\n"
            "\nOptions:\n"
            "  -h  --help\t\t\t" "Display this usage information and exit.\n"
            "  -V  --version\t\t\t"
            "Display the program version.\n");
    exit(EXIT_SUCCESS);
}

// function to pass flags and arguments
void parse_args(int argc, char *argv[]){
    int opt;
    // struct to define argument flags
    struct option longopts[] = {
        { "help", no_argument, NULL, 'h' },
        { "version", no_argument, NULL, 'V' },
        { 0, 0, NULL, 0 }
    };

    // argument parsing
    while((opt = getopt_long(argc, argv, "hV", longopts, 0)) != -1 ){
        switch(opt){
        case 'h':
            print_usage(stdout, argv[0]);
            exit(EXIT_SUCCESS);
        case 'V':
            printf("AlteMatrix [Version %s %s]\n", PROGRAM_VERSION, PROGRAM_DEVELOPMENT_STAGE);
            exit(EXIT_SUCCESS);
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