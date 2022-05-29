#ifndef module
struct module {
    char *name;
    char *version;
    char *development_stage;
};

struct module AlteMatrix = {"AlteMatrix", "0.1.0", "beta"};
struct module IPv4 = {"IPv4", "0.1.0", "preview"};
struct module IPv6 = {"IPv6", "0.1.0", "preview"};

#endif
