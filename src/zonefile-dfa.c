#include "zonefile-dfa.h"
#include <string.h>



void mydfa_init(struct MyDFA *dfa)
{
	memset(dfa, 0, sizeof(*dfa));

	memset(dfa->char_to_symbol, MAX_DFA_SYMBOLS-1, 256);
	memset(dfa->symbol_to_char, '*', 256);
	memset(dfa->table, 0xFF, sizeof(dfa->table));
	dfa->accept_start = 0xFF;
	dfa->accepts[255 - dfa->accept_start] = 0xFFFFFFFF;

	/* Create symbol for unknown character */
	
	/* Create symbols for spaces */
	dfa->symbol_to_char[0] = ' ';
	dfa->char_to_symbol[' '] = 0;
	dfa->char_to_symbol['\t'] = 0;
	dfa->char_to_symbol['\r'] = 0;

	dfa->symbol_to_char[1] = '\n';
	dfa->char_to_symbol['\n'] = 1;

    dfa->symbol_to_char[2]  = '(';
    dfa->char_to_symbol['('] = 2;

    dfa->symbol_to_char[3]  = ')';
    dfa->char_to_symbol[')'] = 3;


	dfa->symbol_count = 4;

	/* Create initial space transitions */
	dfa->table[0][0] = 0;

    /* Create accept state for parentheses */
    {
        unsigned accept_state = --dfa->accept_start;
    	dfa->accepts[0xFF - accept_state] = 0;
        dfa->table[0][dfa->char_to_symbol[')']] = (dfa_t)accept_state;
        dfa->table[0][dfa->char_to_symbol['(']] = (dfa_t)accept_state;
    }
}

void mydfa_add_symbols(struct MyDFA *dfa, const unsigned char *str, unsigned length)
{
	unsigned i;

	for (i=0; i<length; i++) {
		unsigned char c = str[i];
		unsigned char c2 = c;
		if ('a' <= c && c <= 'z')
			c -= 32;
		if ('A' <= c && c <= 'Z')
			c2 = c + 32;

		if (dfa->char_to_symbol[c] == MAX_DFA_SYMBOLS-1) {
			dfa->char_to_symbol[c] = (unsigned char)dfa->symbol_count;
			dfa->char_to_symbol[c2] = (unsigned char)dfa->symbol_count;
			dfa->symbol_to_char[dfa->symbol_count] = c;
			dfa->symbol_count++;
		}
	}
}


void mydfa_add_pattern(struct MyDFA *dfa, const unsigned char *str, unsigned length, unsigned id)
{
	unsigned state = 0;
	unsigned i;
	unsigned char c;
	unsigned char symbol;
	unsigned accept_state = --dfa->accept_start;

	/* Figure out "accept state */
	dfa->accepts[0xFF - accept_state] = id;

	/* Add all the real characters */
	for (i=0; i<length; i++) {
		c = str[i];
		symbol = dfa->char_to_symbol[c];

		if (dfa->table[state][symbol] == 0xFF) {
			dfa->table[state][symbol] = (unsigned char)++dfa->state_count;
		}
		state = dfa->table[state][symbol];
	}

	/* Add a transition for newline */
	c = '\n';
	symbol = dfa->char_to_symbol[c];
	dfa->table[state][symbol] = (unsigned char)accept_state;

	/* Add  the "space" transitions */
	c = ' ';
	symbol = dfa->char_to_symbol[c];
	if (dfa->table[state][symbol] == 0xFF) {
		dfa->table[state][symbol] = (unsigned char)++dfa->state_count;
		state = dfa->table[state][symbol];
		for (i=0; i<MAX_DFA_SYMBOLS; i++)
			dfa->table[state][i] = (unsigned char)accept_state;
		dfa->table[state][0] = (unsigned char)state;
	}

}


unsigned mydfa_search(struct MyDFA *dfa, unsigned *in_state, const void *in_buf, unsigned *offset, unsigned length)
{
	const unsigned char *buf = (const unsigned char *)in_buf;
	unsigned i = *offset;
	unsigned state = *in_state;
	unsigned accept_start = dfa->accept_start;
	SMALL_DFA_TABLE *table = &dfa->table;
	const unsigned char *char_to_symbol = dfa->char_to_symbol;
	

	while (i<length) {
		state = (*table)[state][char_to_symbol[buf[i]]];
		if (state >= accept_start)
			break;
		i++;
	}

	*in_state = state;
	*offset = i;
	if (state >= accept_start)
		return dfa->accepts[(255 - state) & 0xFF];
	else
		return 0;
}


unsigned
mydfa_selftest(struct MyDFA *dfa, const void *buf, unsigned expected_id)
{
	unsigned state = 0;
	unsigned offset = 0;
	unsigned x;
	unsigned buf_length = (unsigned)strlen((const char *)buf);

	x = mydfa_search(dfa, &state, buf, &offset, buf_length);
	if (x == 0)
		return expected_id == 0;
	else
		return x == expected_id;
}

