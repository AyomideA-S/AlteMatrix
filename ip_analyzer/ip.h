/* 
IPv4 Address Analyzer by AyomideA-S (https://github.com/AyomideA-S)
NOTE: This code includes knowledge acquired from David Bombal's "Ethical Hacking for Beginners" course on Udemy!
You can access the course at: 
https://www.udemy.com/course/pratcical-ethical-hacking-for-beginners/?src=sac&kw=Ethical+hacking+for+beginner
*/

// array of subnet masks
char *MASKS[32] = {"128.0.0.0", "192.0.0.0", "224.0.0.0", "240.0.0.0", "248.0.0.0", "252.0.0.0", "254.0.0.0", "255.0.0.0", 
    "255.128.0.0", "255.192.0.0", "255.224.0.0", "255.240.0.0", "255.248.0.0", "255.252.0.0", "255.254.0.0", "255.255.0.0", 
    "255.255.128.0", "255.255.192.0", "255.255.224.0", "255.255.240.0", "255.255.248.0", "255.255.252.0", "255.255.254.0", 
    "255.255.255.0", "255.255.255.128", "255.255.255.192", "255.255.255.224", "255.255.255.240", "255.255.255.248", 
    "255.255.255.252", "255.255.255.254", "255.255.255.255"};



// function to validate user input
int validate_input(int *ipv4, char *subnet, int *subnets, int mask) {
    for(int i = 0; i < 4; i++) {
        if(ipv4[i] == -1)
            return 1;
    }
    for(int i = 0; i < 4; i++) {
        if(ipv4[i] > 255 || ipv4[i] < 0)
            return 11;
    }

    if(subnet != ""){
        for(int i = 0; i < 4; i++) {
            if(subnets[i] == -1)
                return 10;
        }
        for(int i = 0; i < 4; i++) {
            if(subnets[i] > 255 || subnets[i] < 0)
                return 100;
        }
    }
    
    if(mask)
        if(mask > 32 || mask < 1) return 3;
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
void present_ip(char* ip, int *ipv4, FILE *stream){
    char BINARY[9] = {0,0,0,0,0,0,0,0,'\0'};

    // plain ipv4 format
    fprintf(stream, "\n %19s IPv4 %19s\n|", " "," ");
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

    fprintf(stream, "%16s Subnet mask %16s\n", " "," ");
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

// subnet mask
void present_mask(int mask, FILE *stream){
    fprintf(stream, "\nThis is a %d-bit subnet mask.\n", mask);
    int hosts = 32 - mask;
    fprintf(stream, "Host Bits: %d\n", hosts);
    int supported_hosts = pow(2, hosts) - 2;
    fprintf(stream, "Number of supported Hosts: %d\n", supported_hosts);
    fprintf(stream, "Total IPs: %d\n", supported_hosts+2);
}

// present the summary
int summarize(char* ip, int *ipv4, int *subnets, int zero, FILE *stream){
    char class;
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
    class = get_class(ipv4);

    fprintf(stream, "\nSummary\n");
    for(int i = 0; i < 43; i++){
        fprintf(stream, "-");
    }
    
    fprintf(stream, "\nNetwork Address: %s\n", ip);
    fprintf(stream, "Class: %c\n", class);

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
}

// mask summary
void yes_mask(int mask, FILE *stream){
    fprintf(stream, "Subnet mask: %s\n", MASKS[mask - 1]);
}

// print help
void print_usage (FILE* stream, char *program_path)
{
    const char *program_name = strrchr(program_path, '/');
    program_name = program_name ? program_name + 1 : program_path;
    fprintf (stream, "Usage:  %s -i|--ip <IPv4_address> [OPTIONS]\n", program_name);
    fprintf (stream,
            "  -h  --help\t\t\t" "Display this usage information and exit.\n"
            "  -i  --ip <IPv4_address>\t" "Takes IPv4 address.\n"
            "  -s  --subnet <subnet>\t\t" "Takes IPv4 subnet address.\n"
            "  -m  --mask <mask>\t\t" "Takes IPv4 subnet mask.\n"
            "  -f  --file=[FILENAME]\t\t" "Write all output to a file (defaults to ipanalysis.txt).\n"
            "  -V  --version\t\t\t"
            "Display the program version.\n");
    exit(EXIT_SUCCESS);
}