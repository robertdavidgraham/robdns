#ifndef LOGGER_H
#define LOGGER_H

extern int verbosity; /* defined in logger.c */

enum LogLevel {
    L_CRIT,   /*  "critical" */
    L_ERR,      /*  "error" */
    L_WARN,    /*  "warning" */
    L_NOTE,     /*  "notice" */
    L_INFO,       /*  "info" */
    L_DBG0,
    L_DBG1,
    L_DBG2,
    L_DBG3,
    L_DYNAMIC=L_DBG0+100,
};

enum LogCategory {
    C_ZONEFILE,     /* errors parsing zonefiles */
    C_CLIENT,
    C_CONFIG,
    C_DATABASE,
    C_DNSSEC,
    C_GENERAL,    /* anything not in another category */
    C_NETWORK,
    C_NOTIFY,     /* all NOTIFY operations */
    C_QUERIES,
    C_RATE_LIMIT,
    C_SECURITY,   /* approval and denial of requests */
    C_UPDATE,     /* all UPDATE dyn-DNS operations */
    C_UPDATE_SECURITY, /* approval and denial of UPDATE requests with dyn-DNS */
    C_XFER_IN,    /* zone transfers the server is receiving */
    C_XFER_OUT,   /* zone transfers the server is sending */
};

//void LOG(enum LogLevel lvl, enum LogCategory cat, const char *fmt, ...);

void LOG_CRIT(enum LogCategory cat, const char *fmt, ...);
void LOG_ERR(enum LogCategory cat, const char *fmt, ...);
void LOG_WARN(enum LogCategory cat, const char *fmt, ...);
void LOG_INFO(enum LogCategory cat, const char *fmt, ...);
void LOG_DBG(enum LogCategory cat, int debug_level, const char *fmt, ...);

#endif
