#ifndef CONF_ERROR_H
#define CONF_ERROR_H
struct ConfParse;
struct CF_Token;

//void WARNING(struct CF_Token token, const char *fmt, ...);

void CONF_ERR(const struct ConfParse *parse, const struct CF_Token *token, const char *fmt, ...);

/* when the 'name' of a statement is unknown */
void CONF_OPTION_UNKNOWN(const struct ConfParse *parse, const struct CF_Token *token);

/* when the value has been duplicated*/
void CONF_OPTION_DUPLICATE(const struct ConfParse *parse, const struct CF_Token *token);

/* when the 'value' of a statement is unknown or bad*/
void CONF_VALUE_BAD(const struct ConfParse *parse, const struct CF_Token *token);

/* when the 'value' of a statement is missing */
void CONF_VALUE_MISSING(const struct ConfParse *parse, const struct CF_Token *token);

void CONF_FEATURE_UNSUPPORTED(const struct ConfParse *parse, const struct CF_Token *token);

/* like 'feature-supported', but specifically this feature since it 
 * appears in so many places */
void CONF_RECURSION_UNSUPPORTED(const struct ConfParse *parse, const struct CF_Token *token);

#endif
