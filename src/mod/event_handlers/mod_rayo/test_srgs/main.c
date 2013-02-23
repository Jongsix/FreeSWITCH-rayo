
#include <switch.h>
#include "srgs.h"


static const char *adhearsion_collect_digit =
	"<grammar xmlns=\"http://www.w3.org/2001/06/grammar\" version=\"1.0\" xml:lang=\"en-US\" mode=\"dtmf\" root=\"inputdigits\">"
	"  <rule id=\"inputdigits\" scope=\"public\">\n"
	"    <one-of>\n"
	"      <item>0</item>\n"
	"      <item>1</item>\n"
	"      <item>2</item>\n"
	"      <item>3</item>\n"
	"      <item>4</item>\n"
	"      <item>5</item>\n"
	"      <item>6</item>\n"
	"      <item>7</item>\n"
	"      <item>8</item>\n"
	"      <item>9</item>\n"
	"      <item>#</item>\n"
	"      <item>*</item>\n"
	"    </one-of>\n"
	"  </rule>\n"
	"</grammar>\n";


static void assert_equals(char *test, char *expected_str, int expected, int actual)
{
	if (expected != actual) {
		printf("\t%s\tFAIL\texpected = %i(%s), actual = %i\n", test, expected, expected_str, actual);
		exit(1);
	} else {
		printf("\t%s\tPASS\n", test);
	}
}

#define ASSERT_EQUALS(expected, actual) assert_equals(#actual, #expected, expected, actual)

#define TEST(name) printf("Testing " #name "...\n"); name(); printf(#name "\tPassed!\n");

static int adhearsion_single_digit(void)
{
	switch_memory_pool_t *pool;
	struct srgs_parser *parser;

	switch_core_new_memory_pool(&pool);
	parser = srgs_parser_new(pool, "1234");
	srgs_parse(parser, adhearsion_collect_digit);

	ASSERT_EQUALS(MT_MATCH, srgs_match(parser, "0"));
	ASSERT_EQUALS(MT_MATCH, srgs_match(parser, "1"));
	ASSERT_EQUALS(MT_MATCH, srgs_match(parser, "2"));
	ASSERT_EQUALS(MT_MATCH, srgs_match(parser, "3"));
	ASSERT_EQUALS(MT_MATCH, srgs_match(parser, "4"));
	ASSERT_EQUALS(MT_MATCH, srgs_match(parser, "5"));
	ASSERT_EQUALS(MT_MATCH, srgs_match(parser, "6"));
	ASSERT_EQUALS(MT_MATCH, srgs_match(parser, "7"));
	ASSERT_EQUALS(MT_MATCH, srgs_match(parser, "8"));
	ASSERT_EQUALS(MT_MATCH, srgs_match(parser, "9"));
	ASSERT_EQUALS(MT_MATCH, srgs_match(parser, "#"));
	ASSERT_EQUALS(MT_MATCH, srgs_match(parser, "*"));
	ASSERT_EQUALS(MT_NO_MATCH, srgs_match(parser, "A"));
	ASSERT_EQUALS(MT_NO_MATCH, srgs_match(parser, "22"));
	ASSERT_EQUALS(MT_NO_MATCH, srgs_match(parser, "223"));
	ASSERT_EQUALS(MT_NO_MATCH, srgs_match(parser, "0123456789*#"));

	switch_core_destroy_memory_pool(&pool);
	return 1;
}


int main(int argc, char **argv)
{
	TEST(adhearsion_single_digit);
	return 0;
}

