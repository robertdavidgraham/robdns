#include "configuration.h"
#include "conf-trackfile.h"
#include "util-realloc2.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>


/****************************************************************************
 ****************************************************************************/
struct Configuration *cfg_create(void)
{
    struct Configuration *cfg;

    cfg = REALLOC2(0, 1, sizeof(*cfg));
    memset(cfg, 0, sizeof(cfg[0]));

    cfg->zone_defaults = REALLOC2(0, 1, sizeof(*cfg->zone_defaults));
    memset(cfg->zone_defaults, 0, sizeof(*cfg->zone_defaults));

    /* Create a subsystem that keeps track of all the configuration files */
    cfg->tf = conf_trackfile_create();

    /*
     * Set some defaults
     */
    cfg_load_string(cfg, "options { port 53; };");

    assert(cfg->data_plane.port == 53);

    return cfg;
}

/****************************************************************************
 ****************************************************************************/
void
free2(char *str)
{
    if (str)
        free(str);
}

/****************************************************************************
 ****************************************************************************/
void cfg_destroy(struct Configuration *cfg)
{
    if (cfg == NULL)
        return;

    free2(cfg->options.directory);
    free2(cfg->options.pid_file);
    free2(cfg->options.hostname);
    free2(cfg->options.server_id);
    free2(cfg->options.version);

    free(cfg);
}


int
cfg_selftest(void)
{
    struct Configuration *cfg;

    cfg = cfg_create();

    cfg_load_string(cfg, "options {\n listen-on port 53 { any; { 127.0.0.1; ::1; }; }; };");
    
    cfg_destroy(cfg);

    return 0;
}
