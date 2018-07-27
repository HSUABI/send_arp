#include "swap_endian.h"

int swap_word_endian(unsigned short swap)
{
	return (swap << 8 | swap >> 8);
}