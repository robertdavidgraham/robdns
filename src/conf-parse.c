#include "conf-parse.h"
#include "conf-error.h"
#include "util-realloc2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>

/****************************************************************************
 ****************************************************************************/
struct Token {
    size_t offset;
    size_t length;
    const char *filename;
    unsigned is_string:1;
    unsigned linenumber:31;
};

/****************************************************************************
 ****************************************************************************/
struct Item {
    struct Token *tokens;
    size_t token_current;
    size_t token_count;

    struct Item *items;
    size_t item_current;
    size_t item_count;

    struct Item *parent;

    unsigned line_number;
    const char *filename;
};

const char *confparse_err_file_line(const struct CF_Child *node, size_t *line_number)
{
    const struct Item *item = (const struct Item*)node->internals;
    if (line_number)
        *line_number = item->line_number;
    return item->filename;
}

/****************************************************************************
 ****************************************************************************/
struct ConfParse
{
    unsigned state;
    struct {
        char *data;
        size_t offset;
        size_t max;
    } buf;

    struct Item root[1];
    struct Item *item;

    size_t line_number;
    size_t line_offset;

    CONF_STATEMENT_CALLBACK callback_fn;
    void *callback_data;

    char *filename;
};

/***************************************************************************
 ***************************************************************************/
void
CONF_ERR(const struct ConfParse *parse, const struct CF_Token *token, const char *fmt, ...)
{
    va_list marker;
    unsigned i;

    va_start(marker, fmt);
    fprintf(stderr, "%s:%u:", token->filename, token->linenumber + 1);
    for (i=0; i<32 && i<token->name_length; i++) {
        if (isprint(token->name[i]&0xFF) && token->name[i] != '<')
            printf("%c", token->name[i]);
    }
    if (i == 16)
        fprintf(stderr, "...: ");
    else
        fprintf(stderr, ": ");
    vfprintf(stderr, fmt, marker);
    va_end(marker);
}

/* when the 'name' of a statement is unknown */
void CONF_OPTION_UNKNOWN(const struct ConfParse *parse, const struct CF_Token *token)
{
    CONF_ERR(parse, token, "unknown option\n");
}

/* when the value has been duplicated*/
void CONF_OPTION_DUPLICATE(const struct ConfParse *parse, const struct CF_Token *token)
{
    CONF_ERR(parse, token, "option redefined\n");
}

/* when the 'value' of a statement is unknown or bad*/
void CONF_VALUE_BAD(const struct ConfParse *parse, const struct CF_Token *token)
{
    CONF_ERR(parse, token, "unexpected value\n");
}

/* when the 'value' of a statement is missing */
void CONF_VALUE_MISSING(const struct ConfParse *parse, const struct CF_Token *token)
{
    CONF_ERR(parse, token, "missing value\n");
}
void CONF_FEATURE_UNSUPPORTED(const struct ConfParse *parse, const struct CF_Token *token)
{
    CONF_ERR(parse, token, "feature not supported\n");
}
void CONF_RECURSION_UNSUPPORTED(const struct ConfParse *parse, const struct CF_Token *token)
{
    CONF_ERR(parse, token, "forward/recursive lookups not supported\n");
}

/****************************************************************************
 ****************************************************************************/
struct CF_Token 
confparse_node_gettoken(const struct ConfParse *parser, const struct CF_Child *node, size_t index)
{
    const struct Item *item = (const struct Item *)node->internals;
    const struct Token *token = &item->tokens[index];
    struct CF_Token result;


    if (item->token_count <= index) {
        result.is_string = 0;
        result.name = "";
        result.name_length = 0;
        if (item->token_count) {
            result.filename = item->tokens[item->token_count-1].filename;
            result.linenumber = item->tokens[item->token_count-1].linenumber;
        } else {
            result.filename = item->filename;
            result.linenumber = item->line_number;
        }
    } else {
        result.is_string = token->is_string;
        result.name = parser->buf.data + token->offset;
        result.name_length = (unsigned)token->length;
        result.filename = token->filename;
        result.linenumber = token->linenumber;
    }

    return result;
}


/****************************************************************************
 ****************************************************************************/
struct CF_Child
confparse_node_getchild(const struct ConfParse *parser, const struct CF_Child *node, size_t index)
{
    const struct Item *parent = (const struct Item *)node->internals;
    const struct Item *item = &parent->items[index];
    struct CF_Child result;

    result.child_count = item->item_count;
    result.internals = (struct CF_Internals *)item;
    result.token_count = item->token_count;

    if (result.token_count == 0) {
        result.name = "";
        result.name_length = 0;
    } else {
        result.name = item->tokens->offset + parser->buf.data;
        result.name_length = item->tokens->length;
    }

    return result;
}

/****************************************************************************
 ****************************************************************************/
void
confparse_destroy_item(struct Item *item)
{
    size_t i;

    if (item->token_count)
        free(item->tokens);

    for (i=0; i<item->item_count; i++) {
        confparse_destroy_item(&item->items[i]);
    }
    
    if (item->item_count)
        free(item->items);

}

/****************************************************************************
 * Print one node within the parsed tree.
 ****************************************************************************/
static void
confparse_print_node(struct ConfParse *parser, FILE *fp, struct Item *item, unsigned depth)
{
    size_t i;


    for (i=0; i < depth * 4; i++)
        fprintf(fp, " ");
    for (i = 0; i < item->token_count; i++) {
        struct Token *token = &item->tokens[i];
        const char *space = " ";
        if (i + 1 == item->token_count)
            space = "";
        if (token->is_string)
            fprintf(fp, "\"%.*s\"%s", (unsigned)token->length, parser->buf.data + token->offset, space);
        else
            fprintf(fp, "%.*s%s", (unsigned)token->length, parser->buf.data + token->offset, space);
    }

    if (item->item_count) {
        fprintf(fp, " {\n");
        for (i = 0; i< item->item_count; i++) {
            confparse_print_node(parser, fp, &item->items[i], depth+1);
        }
        for (i=0; i < depth * 4; i++)
            fprintf(fp, " ");
        fprintf(fp, "};\n");
    } else
        fprintf(fp, ";\n");
}

/****************************************************************************
 ****************************************************************************/
void
confparse_print(struct ConfParse *parser, FILE *fp)
{
    size_t i;

    for (i = 0; i < parser->root->item_count; i++) {
        struct Item *item = &parser->root->items[i];
        confparse_print_node(parser, fp, item, 0);
    }
}

/****************************************************************************
 ****************************************************************************/
void
confparse_print_statement(struct ConfParse *parser, FILE *fp)
{
    size_t i;

    for (i = 0; i < parser->root->item_count && i < 1; i++) {
        struct Item *item = &parser->root->items[i];
        confparse_print_node(parser, fp, item, 0);
    }
}

/****************************************************************************
 ****************************************************************************/
static struct Item *
GET_ITEM(struct ConfParse *parser)
{
    struct Item *parent;
    struct Item *item;

    if (parser->item == NULL)
        parser->item = parser->root;
    parent = parser->item;

    if (parent->item_current >= parent->item_count) {
        parent->item_count++;
        parent->items = REALLOC2(parent->items, parent->item_count, sizeof(parent->items[0]));
        
        item = &parent->items[parent->item_current];
        memset(item, 0, sizeof(*item));
        item->parent = parent;
        item->filename = parser->filename;
        item->line_number = (unsigned)parser->line_number;
    }
    item = &parent->items[parent->item_current];
    return item;
}

/****************************************************************************
 ****************************************************************************/
static void
DESCEND(struct ConfParse *parser)
{
    parser->item = GET_ITEM(parser);
}

/****************************************************************************
 ****************************************************************************/
static void
ASCEND(struct ConfParse *parser)
{
    parser->item = parser->item->parent;
}

/****************************************************************************
 ****************************************************************************/
static struct Token *
GET_TOKEN(struct ConfParse *parser)
{
    struct Item *item;
    struct Token *token;

    item = GET_ITEM(parser);

    if (item->token_current >= item->token_count) {
        item->token_count++;
        item->tokens = REALLOC2(item->tokens, item->token_count, sizeof(item->tokens[0]));
        token = &item->tokens[item->token_current];
        memset(token, 0, sizeof(token[0]));
        token->offset = parser->buf.offset;
        token->filename = parser->filename;
        token->linenumber = (unsigned)parser->line_number;

    }
    token = &item->tokens[item->token_current];

    return token;
}

/****************************************************************************
 ****************************************************************************/
static void 
APPEND_TOKEN(struct ConfParse *parser, unsigned char c)
{
    struct Token *token = GET_TOKEN(parser);

    if (parser->buf.offset + 2 >= parser->buf.max) {
        parser->buf.max = parser->buf.max * 2 + 1;
        parser->buf.data = REALLOC2(parser->buf.data, parser->buf.max + 2, 1);
    }

    parser->buf.data[parser->buf.offset++] = c;
    token->length++;
}

/****************************************************************************
 ****************************************************************************/
static void
END_TOKEN(struct ConfParse *parser, unsigned is_string)
{
    struct Item *item = GET_ITEM(parser);
    struct Token *token = GET_TOKEN(parser);

    /*
     * Append a NUL, so that we get nice pretty nul terminated
     * strings
     */
    if (parser->buf.offset + 2 >= parser->buf.max) {
        parser->buf.max = parser->buf.max * 2 + 1;
        parser->buf.data = REALLOC2(parser->buf.data, parser->buf.max + 2, 1);
    }
    parser->buf.data[parser->buf.offset++] = '\0';

    //printf("%.*s \n", token->length, token->offset + parser->buf.data);
    token->is_string = is_string;
    item->token_current++;
}

/****************************************************************************
 ****************************************************************************/
static void
END_ITEM(struct ConfParse *parser)
{
    parser->item->item_current++;
    if (parser->item == parser->root) {
        struct CF_Child node;
        struct Item *item = parser->root->items;

        if (item->token_count == 0) {
            node.name = "";
            node.name_length = 0;
        } else {
            struct Token * token = item->tokens;
            node.name = parser->buf.data + token->offset;
            node.name_length = token->length;
        }
        node.token_count = item->token_count;
        node.child_count = item->item_count;
        node.internals = (void*)item;

        parser->callback_fn(parser, parser->callback_data, &node);
        confparse_destroy_item(parser->root);
        memset(parser->root, 0, sizeof(parser->root[0]));
    }
}

/****************************************************************************
 ****************************************************************************/
static void
END_OF_LINE(struct ConfParse *parser, size_t i)
{
    parser->line_number++;
    parser->line_offset = i;
}

/****************************************************************************
 ****************************************************************************/
void
vERROR(const struct ConfParse *parser, size_t i, const char *fmt, va_list marker)
{
    fprintf(stderr, "%s:%u:%u: ", 
        parser->filename,
        (unsigned)parser->line_number,
        (unsigned)(i - parser->line_offset)
        );

    vfprintf(stderr, fmt, marker);
    fflush(stderr);
}

/****************************************************************************
 ****************************************************************************/
static void
ERROR(struct ConfParse *parser, size_t i, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    vERROR(parser, i, fmt, marker);
    va_end(marker);
}



/****************************************************************************
 ****************************************************************************/
void
confparse_parse(struct ConfParse *parser, const unsigned char *data, size_t sizeof_data)
{
    size_t i;
    enum {
        $START_OF_LINE=0,
        $START_SLASH,
        $COMMENT,
        $COMMENT_C,
        $COMMENT_C_STAR,
        $START_TOKEN,
        $TOKEN,
        $QUOTE,
    } state = (int)parser->state;

    for (i=0; i<sizeof_data; i++) 
    switch (state) {
    case $START_OF_LINE:
        if (data[i] == '\n') {
            END_OF_LINE(parser, i);
            state = $START_OF_LINE;
            continue;
        } else if (isspace(data[i])) {
            continue;
        } else if (data[i] == '/') {
            state = $START_SLASH;
            continue;
        } else if (data[i] == '#') {
            state = $COMMENT;
            continue;
        }

        state = $START_TOKEN;
        /* drop down */

    case $START_TOKEN:
start_token:
        if (data[i] == '\n') {
            END_OF_LINE(parser, i);
            state = $START_OF_LINE;
            continue;
        } else if (isspace(data[i])) {
            continue;
        } else if (data[i] == '{') {
            DESCEND(parser);
            continue;
        } else if (data[i] == '}') {
            ASCEND(parser);
            continue;
        } else if (data[i] == '\"') {
            state = $QUOTE;
            continue;
        } else if (data[i] == ';') {
            END_ITEM(parser);
            state = $START_TOKEN;
            continue;
        } else if (data[i] == '/') {
            state = $START_SLASH;
            continue;
        } else if (data[i] == '#') {
            state = $COMMENT;
            continue;
        }
        state = $TOKEN;
        /* drop down */
    case $TOKEN:
        if (data[i] == '\n') {
            END_OF_LINE(parser, i);
            state = $START_OF_LINE;
            END_TOKEN(parser, 0);
            continue;
        } else if (isspace(data[i]) || data[i] == '{' || data[i] == ';') {
            END_TOKEN(parser, 0);
            state = $START_TOKEN;
            goto start_token;
        } else {
            APPEND_TOKEN(parser, data[i]);
        }
        break;

    case $QUOTE:
        if (data[i] == '\n') {
            ERROR(parser, i, "newline in string\n");
            END_TOKEN(parser, 1);
            END_OF_LINE(parser, i);
            state = $START_OF_LINE;
        } else if (data[i] == '"') {
            END_TOKEN(parser, 1);
            state = $START_OF_LINE;
            continue;
        } else if (data[i] == '\\') {
            ERROR(parser, i, "unexpected slash\n");
        } else {
            APPEND_TOKEN(parser, data[i]);
        }
        break;
    case $START_SLASH:
        if (data[i] == '\n') {
            ERROR(parser, i, "unexpected character: %c", '/');
            END_OF_LINE(parser, i);
            state = $START_OF_LINE;
            continue;
        } else if (data[i] == '*') {
            state = $COMMENT_C;
            continue;
        } else if (data[i] == '/') {
            state = $COMMENT;
            continue;
        } else {
            ERROR(parser, i, "unexpected character: %c", '/');
            state = $COMMENT;
            continue;
        }
        break;

    case $COMMENT_C:
        if (data[i] == '\n') {
            END_OF_LINE(parser, i);
            continue;
        } else if (data[i] == '*') {
            state = $COMMENT_C_STAR;
            continue;
        }
        break;

    case $COMMENT_C_STAR:
        if (data[i] == '\n') {
            END_OF_LINE(parser, i);
            state = $COMMENT_C;
            continue;
        } else if (data[i] == '/') {
            state = $START_TOKEN;
            continue;
        } else
            state = $COMMENT_C;
        break;

    case $COMMENT:
        if (data[i] == '\n') {
            END_OF_LINE(parser, i);
            state = $START_OF_LINE;
            continue;
        }
        break;

    default:
        ERROR(parser, i, "unknown state\n");
        state = $COMMENT;
        break;

    }

    parser->state = state;
}


/****************************************************************************
 ****************************************************************************/
struct ConfParse *
confparse_create(const char *filename, CONF_STATEMENT_CALLBACK callback, void *data)
{
    struct ConfParse *parser;

    parser = MALLOC2(sizeof(*parser));

    memset(parser, 0, sizeof(*parser));

    parser->callback_fn = callback;
    parser->callback_data = data;

    parser->filename = MALLOC2(strlen(filename)+1);
    memcpy(parser->filename, filename, strlen(filename)+1);

    return parser;
}



/****************************************************************************
 ****************************************************************************/
void
confparse_destroy(struct ConfParse *parser)
{
    if (parser == NULL)
        return;
    
    confparse_destroy_item(parser->root);

    if (parser->buf.max)
        free(parser->buf.data);

    if (parser->filename)
        free(parser->filename);
}
