#ifndef ZONE_DFA_H
#define ZONE_DFA_H

#define MAX_DFA_SYMBOLS 32
typedef unsigned char dfa_t;
typedef	dfa_t SMALL_DFA_TABLE[256][MAX_DFA_SYMBOLS];


struct MyDFA
{
	unsigned char char_to_symbol[256];
	unsigned char symbol_to_char[256];
	unsigned symbol_count;
	unsigned state_count;
	unsigned accept_start;
	SMALL_DFA_TABLE table;
	unsigned accepts[64];
};


void mydfa_init(struct MyDFA *dfa);
void mydfa_add_symbols(struct MyDFA *dfa, const unsigned char *str, unsigned length);
void mydfa_add_pattern(struct MyDFA *dfa, const unsigned char *str, unsigned length, unsigned id);
unsigned mydfa_search(struct MyDFA *dfa, unsigned *in_state, const void *in_buf, unsigned *offset, unsigned length);
unsigned mydfa_selftest(struct MyDFA *dfa, const void *buf, unsigned expected_id);


#endif
