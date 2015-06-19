#include "configuration.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *version;

struct Checkconf
{
    unsigned is_print_filenames;
    unsigned is_checkzone;
    unsigned is_checkzone_journal;
    const char *filename;
};

static void
parse_command_line(struct Checkconf *check, int argc, char *argv[])
{
    int i;

    for (i=1; i<argc; i++) {
        if (strcmp(argv[i], "--checkconf") == 0 || strcmp(argv[i], "checkconf") == 0)
            continue;
        if (argv[i][0] == '-')
        switch (argv[i][1]) {
        case 'h':
            fprintf(stderr, "usage: robdns --checkconf [-h] [-p] [-v] [-z] named.conf\n");
            exit(1);
            break;
        case 'p':
            check->is_print_filenames = 1;
            break;
        case 'v':
            fprintf(stderr, "%s\n", version);
            exit(1);
            break;
        case 'z':
            check->is_checkzone = 1;
            break;
        case 'j':
            check->is_checkzone_journal = 1;
            break;
        } else {
            if (check->filename != 0) {
                fprintf(stderr, "only one configuration filename may be specified\n");
                exit(1);
            }
            check->filename = argv[i];
        }
    }

    if (check->filename == 0) {
        fprintf(stderr, "at least one filename must be specified\n");
        exit(1);
    }
}

int checkconf(int argc, char *argv[])
{
    struct Checkconf check;
    struct Configuration *cfg;

    memset(&check, 0, sizeof(check));

    parse_command_line(&check, argc, argv);

    cfg = cfg_create();
    cfg_parse_file(cfg, check.filename);

    cfg_destroy(cfg);
    return 0;
}


