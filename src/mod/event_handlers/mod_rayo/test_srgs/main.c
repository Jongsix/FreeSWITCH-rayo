

#include <switch.h>
#include "srgs.h"


static void assert_equals(const char *test, const char *expected_str, int expected, int actual, const char *file, int line)
{
	if (expected != actual) {
		printf("TEST\t%s\tFAIL\t%s\t%i\t!=\t%i\t%s:%i\n", test, expected_str, expected, actual, file, line);
		exit(1);
	} else {
		printf("TEST\t%s\tPASS\n", test);
	}
}

static void assert_string_equals(const char *test, const char *expected, const char *actual, const char *file, int line)
{
	if (!actual || strcmp(expected, actual)) {
		printf("TEST\t%s\tFAIL\t\t%s\t!=\t%s\t%s:%i\n", test, expected, actual, file, line);
		exit(1);
	} else {
		printf("TEST\t%s\tPASS\n", test);
	}
}

static void assert_not_null(const char *test, const void *actual, const char *file, int line)
{
	if (!actual) {
		printf("TEST\t%s\tFAIL\t\t\t\t\t%s:%i\n", test, file, line);
		exit(1);
	} else {
		printf("TEST\t%s\tPASS\n", test);
	}
}

static void assert_null(const char *test, const void *actual, const char *file, int line)
{
	if (actual) {
		printf("TEST\t%s\tFAIL\t\t\t\t\t%s:%i\n", test, file, line);
		exit(1);
	} else {
		printf("TEST\t%s\tPASS\n", test);
	}
}

#define ASSERT_EQUALS(expected, actual) assert_equals(#actual, #expected, expected, actual, __FILE__, __LINE__)
#define ASSERT_STRING_EQUALS(expected, actual) assert_string_equals(#actual, expected, actual, __FILE__, __LINE__)
#define ASSERT_NOT_NULL(actual) assert_not_null(#actual " not null", actual, __FILE__, __LINE__)
#define ASSERT_NULL(actual) assert_null(#actual " is null", actual, __FILE__, __LINE__)

#define SKIP_ASSERT_EQUALS(expected, actual) if (0) { ASSERT_EQUALS(expected, actual); }

#define TEST(name) printf("TEST BEGIN\t" #name "\n"); name(); printf("TEST END\t"#name "\tPASS\n");

#define SKIP_TEST(name) if (0) { TEST(name) };

static const char *adhearsion_ask_grammar =
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

/**
 * Test matching against adhearsion ask grammar
 */
static void test_match_adhearsion_ask_grammar(void)
{
	struct srgs_parser *parser;

	parser = srgs_parser_new("1234");
	ASSERT_EQUALS(1, srgs_parse(parser, adhearsion_ask_grammar));

	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "0"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "1"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "2"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "3"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "4"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "5"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "6"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "7"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "8"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "9"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "#"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "*"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "A"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "27"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "223"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "0123456789*#"));

	srgs_parser_destroy(parser);
}

static const char *multi_digit_grammar =
	"<grammar xmlns=\"http://www.w3.org/2001/06/grammar\" version=\"1.0\" xml:lang=\"en-US\" mode=\"dtmf\" root=\"misc\">"
	"  <rule id=\"misc\" scope=\"public\">\n"
	"    <one-of>\n"
	"      <item>01</item>\n"
	"      <item>13</item>\n"
	"      <item> 24</item>\n"
	"      <item>36 </item>\n"
	"      <item>223</item>\n"
	"      <item>5 5</item>\n"
	"      <item>63</item>\n"
	"      <item>76</item>\n"
	"      <item>8 8 0</item>\n"
	"      <item>93</item>\n"
	"      <item> # 2 </item>\n"
	"      <item>*3</item>\n"
	"      <item>  27</item>\n"
	"    </one-of>\n"
	"  </rule>\n"
	"</grammar>\n";

/**
 * Test matching against grammar with multiple digits per item
 */
static void test_match_multi_digit_grammar(void)
{
	struct srgs_parser *parser;

	parser = srgs_parser_new("1234");
	ASSERT_EQUALS(1, srgs_parse(parser, multi_digit_grammar));

	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "0"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "1"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "2"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "3"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "4"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "5"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "6"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "7"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "8"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "9"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "*"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "A"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "27"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "223"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "0123456789*#"));

	srgs_parser_destroy(parser);
}

static const char *multi_rule_grammar =
	"<grammar xmlns=\"http://www.w3.org/2001/06/grammar\" version=\"1.0\" xml:lang=\"en-US\" mode=\"dtmf\">"
	"  <rule id=\"misc\" scope=\"public\">\n"
	"    <one-of>\n"
	"      <item>01</item>\n"
	"      <item>13</item>\n"
	"      <item> 24</item>\n"
	"      <item>36 </item>\n"
	"      <item>5 5</item>\n"
	"      <item>63</item>\n"
	"    </one-of>\n"
	"  </rule>\n"
	"  <rule id=\"misc2\" scope=\"public\">\n"
	"    <one-of>\n"
	"      <item>76</item>\n"
	"      <item>8 8 0</item>\n"
	"      <item>93</item>\n"
	"      <item> # 2 </item>\n"
	"      <item>*3</item>\n"
	"      <item>  27</item>\n"
	"      <item>223</item>\n"
	"    </one-of>\n"
	"  </rule>\n"
	"</grammar>\n";

static void test_match_multi_rule_grammar(void)
{
	struct srgs_parser *parser;

	parser = srgs_parser_new("1234");
	ASSERT_EQUALS(1, srgs_parse(parser, multi_rule_grammar));

	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "0"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "1"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "2"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "3"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "4"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "5"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "6"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "7"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "8"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "9"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "*"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "A"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "27"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "223"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "0123456789*#"));

	srgs_parser_destroy(parser);
}

static const char *rayo_example_grammar =
	"<grammar mode=\"dtmf\" version=\"1.0\""
	"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	"    xsi:schemaLocation=\"http://www.w3.org/2001/06/grammar\n"
	"                        http://www.w3.org/TR/speech-grammar/grammar.xsd\""
	"    xmlns=\"http://www.w3.org/2001/06/grammar\">\n"
	"\n"
	"    <rule id=\"digit\">\n"
	"    <one-of>\n"
	"       <item> 0 </item>\n"
	"       <item> 1 </item>\n"
	"       <item> 2 </item>\n"
	"       <item> 3 </item>\n"
	"       <item> 4 </item>\n"
	"       <item> 5 </item>\n"
	"       <item> 6 </item>\n"
	"       <item> 7 </item>\n"
	"       <item> 8 </item>\n"
	"       <item> 9 </item>\n"
	"    </one-of>\n"
	"    </rule>\n"
	"\n"
	"    <rule id=\"pin\" scope=\"public\">\n"
	"    <one-of>\n"
	"       <item>\n"
	"         <item repeat=\"4\"><ruleref uri=\"#digit\"/></item>\n"
	"           #\n"
	"         </item>"
	"       <item>"
	"         * 9 \n"
	"       </item>\n"
	"    </one-of>\n"
	"    </rule>\n"
	"</grammar>\n";

static void test_match_rayo_example_grammar(void)
{
	struct srgs_parser *parser;

	parser = srgs_parser_new("1234");
	ASSERT_EQUALS(1, srgs_parse(parser, rayo_example_grammar));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "0"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "1"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "2"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "3"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "4"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "5"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "6"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "7"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "8"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "9"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "*"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "A"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "*9"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "1234#"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "2321#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "27"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "223"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "0123456789*#"));

	srgs_parser_destroy(parser);
}

static const char *bad_ref_grammar =
	"<grammar mode=\"dtmf\" version=\"1.0\""
	"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	"    xsi:schemaLocation=\"http://www.w3.org/2001/06/grammar\n"
	"                        http://www.w3.org/TR/speech-grammar/grammar.xsd\""
	"    xmlns=\"http://www.w3.org/2001/06/grammar\">\n"
	"\n"
	"    <rule id=\"digit\">\n"
	"    <one-of>\n"
	"       <item> 0 </item>\n"
	"       <item> 1 </item>\n"
	"       <item> 2 </item>\n"
	"       <item> 3 </item>\n"
	"       <item> 4 </item>\n"
	"       <item> 5 </item>\n"
	"       <item> 6 </item>\n"
	"       <item> 7 </item>\n"
	"       <item> 8 </item>\n"
	"       <item> 9 </item>\n"
	"    </one-of>\n"
	"    </rule>\n"
	"\n"
	"    <rule id=\"pin\" scope=\"public\">\n"
	"    <one-of>\n"
	"       <item>\n"
	"         <item repeat=\"4\"><ruleref uri=\"#digi\"/></item>\n"
	"           #\n"
	"         </item>"
	"       <item>"
	"         * 9 \n"
	"       </item>\n"
	"    </one-of>\n"
	"    </rule>\n"
	"</grammar>\n";

static const char *adhearsion_ask_grammar_bad =
	"<grammar xmlns=\"http://www.w3.org/2001/06/grammar\" version=\"1.0\" xml:lang=\"en-US\" mode=\"dtmf\" root=\"inputdigits\">"
	"  <rule id=\"inputdigits\" scope=\"public\">\n"
	"    <one-of>\n"
	"      <item>0</item>\n"
	"      <item>1</item\n"
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

static void test_parse_grammar(void)
{
	struct srgs_parser *parser;

	parser = srgs_parser_new("1234");

	ASSERT_EQUALS(1, srgs_parse(parser, adhearsion_ask_grammar));
	ASSERT_EQUALS(0, srgs_parse(parser, adhearsion_ask_grammar_bad));
	ASSERT_EQUALS(0, srgs_parse(parser, NULL));
	ASSERT_EQUALS(0, srgs_parse(NULL, adhearsion_ask_grammar));
	ASSERT_EQUALS(0, srgs_parse(NULL, adhearsion_ask_grammar_bad));
	ASSERT_EQUALS(0, srgs_parse(parser, bad_ref_grammar));

	srgs_parser_destroy(parser);
}

static const char *repeat_item_grammar_bad =
	"<grammar mode=\"dtmf\" version=\"1.0\""
	"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	"    xsi:schemaLocation=\"http://www.w3.org/2001/06/grammar\n"
	"                        http://www.w3.org/TR/speech-grammar/grammar.xsd\""
	"    xmlns=\"http://www.w3.org/2001/06/grammar\">\n"
	"\n"
	"    <rule id=\"pin\" scope=\"public\">\n"
	"       <item>\n"
	"         <item repeat=\"3-1\">4</item>\n"
	"           #\n"
	"       </item>"
	"    </rule>\n"
	"</grammar>\n";

static const char *repeat_item_grammar_bad2 =
	"<grammar mode=\"dtmf\" version=\"1.0\""
	"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	"    xsi:schemaLocation=\"http://www.w3.org/2001/06/grammar\n"
	"                        http://www.w3.org/TR/speech-grammar/grammar.xsd\""
	"    xmlns=\"http://www.w3.org/2001/06/grammar\">\n"
	"\n"
	"    <rule id=\"pin\" scope=\"public\">\n"
	"       <item>\n"
	"         <item repeat=\"-1\">4</item>\n"
	"           #\n"
	"       </item>"
	"    </rule>\n"
	"</grammar>\n";

static const char *repeat_item_grammar_bad3 =
	"<grammar mode=\"dtmf\" version=\"1.0\""
	"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	"    xsi:schemaLocation=\"http://www.w3.org/2001/06/grammar\n"
	"                        http://www.w3.org/TR/speech-grammar/grammar.xsd\""
	"    xmlns=\"http://www.w3.org/2001/06/grammar\">\n"
	"\n"
	"    <rule id=\"pin\" scope=\"public\">\n"
	"       <item>\n"
	"         <item repeat=\"1--1\">4</item>\n"
	"           #\n"
	"       </item>"
	"    </rule>\n"
	"</grammar>\n";

static const char *repeat_item_grammar_bad4 =
	"<grammar mode=\"dtmf\" version=\"1.0\""
	"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	"    xsi:schemaLocation=\"http://www.w3.org/2001/06/grammar\n"
	"                        http://www.w3.org/TR/speech-grammar/grammar.xsd\""
	"    xmlns=\"http://www.w3.org/2001/06/grammar\">\n"
	"\n"
	"    <rule id=\"pin\" scope=\"public\">\n"
	"       <item>\n"
	"         <item repeat=\"ABC\">4</item>\n"
	"           #\n"
	"       </item>"
	"    </rule>\n"
	"</grammar>\n";

static const char *repeat_item_grammar_bad5 =
	"<grammar mode=\"dtmf\" version=\"1.0\""
	"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	"    xsi:schemaLocation=\"http://www.w3.org/2001/06/grammar\n"
	"                        http://www.w3.org/TR/speech-grammar/grammar.xsd\""
	"    xmlns=\"http://www.w3.org/2001/06/grammar\">\n"
	"\n"
	"    <rule id=\"pin\" scope=\"public\">\n"
	"       <item>\n"
	"         <item repeat=\"\">4</item>\n"
	"           #\n"
	"       </item>"
	"    </rule>\n"
	"</grammar>\n";

static const char *repeat_item_grammar_bad6 =
	"<grammar mode=\"dtmf\" version=\"1.0\""
	"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	"    xsi:schemaLocation=\"http://www.w3.org/2001/06/grammar\n"
	"                        http://www.w3.org/TR/speech-grammar/grammar.xsd\""
	"    xmlns=\"http://www.w3.org/2001/06/grammar\">\n"
	"\n"
	"    <rule id=\"pin\" scope=\"public\">\n"
	"       <item>\n"
	"         <item repeat=\"1-Z\">4</item>\n"
	"           #\n"
	"       </item>"
	"    </rule>\n"
	"</grammar>\n";

static const char *repeat_item_grammar =
	"<grammar mode=\"dtmf\" version=\"1.0\""
	"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	"    xsi:schemaLocation=\"http://www.w3.org/2001/06/grammar\n"
	"                        http://www.w3.org/TR/speech-grammar/grammar.xsd\""
	"    xmlns=\"http://www.w3.org/2001/06/grammar\">\n"
	"\n"
	"    <rule id=\"digit\">\n"
	"    <one-of>\n"
	"       <item> 0 </item>\n"
	"       <item> 1 </item>\n"
	"       <item> 2 </item>\n"
	"       <item> 3 </item>\n"
	"       <item> 4 </item>\n"
	"       <item> 5 </item>\n"
	"       <item> 6 </item>\n"
	"       <item> 7 </item>\n"
	"       <item> 8 </item>\n"
	"       <item> 9 </item>\n"
	"    </one-of>\n"
	"    </rule>\n"
	"\n"
	"    <rule id=\"pin\" scope=\"public\">\n"
	"    <one-of>\n"
	"       <item>\n"
	"         <item repeat=\"4-4\"><ruleref uri=\"#digit\"/></item>\n"
	"           #\n"
	"         </item>"
	"       <item>"
	"         * 9 \n"
	"       </item>\n"
	"    </one-of>\n"
	"    </rule>\n"
	"</grammar>\n";

static const char *repeat_item_range_grammar =
	"<grammar mode=\"dtmf\" version=\"1.0\""
	"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	"    xsi:schemaLocation=\"http://www.w3.org/2001/06/grammar\n"
	"                        http://www.w3.org/TR/speech-grammar/grammar.xsd\""
	"    xmlns=\"http://www.w3.org/2001/06/grammar\">\n"
	"\n"
	"    <rule id=\"digit\">\n"
	"    <one-of>\n"
	"       <item> 0 </item>\n"
	"       <item> 1 </item>\n"
	"       <item> 2 </item>\n"
	"       <item> 3 </item>\n"
	"       <item> 4 </item>\n"
	"       <item> 5 </item>\n"
	"       <item> 6 </item>\n"
	"       <item> 7 </item>\n"
	"       <item> 8 </item>\n"
	"       <item> 9 </item>\n"
	"    </one-of>\n"
	"    </rule>\n"
	"\n"
	"    <rule id=\"pin\" scope=\"public\">\n"
	"    <one-of>\n"
	"       <item>\n"
	"         <item repeat=\"4-6\"><ruleref uri=\"#digit\"/></item>\n"
	"           #\n"
	"         </item>"
	"       <item>"
	"         * 9 \n"
	"       </item>\n"
	"    </one-of>\n"
	"    </rule>\n"
	"</grammar>\n";

static const char *repeat_item_optional_grammar =
	"<grammar mode=\"dtmf\" version=\"1.0\""
	"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	"    xsi:schemaLocation=\"http://www.w3.org/2001/06/grammar\n"
	"                        http://www.w3.org/TR/speech-grammar/grammar.xsd\""
	"    xmlns=\"http://www.w3.org/2001/06/grammar\">\n"
	"\n"
	"    <rule id=\"digit\">\n"
	"    <one-of>\n"
	"       <item> 0 </item>\n"
	"       <item> 1 </item>\n"
	"       <item> 2 </item>\n"
	"       <item> 3 </item>\n"
	"       <item> 4 </item>\n"
	"       <item> 5 </item>\n"
	"       <item> 6 </item>\n"
	"       <item> 7 </item>\n"
	"       <item> 8 </item>\n"
	"       <item> 9 </item>\n"
	"    </one-of>\n"
	"    </rule>\n"
	"\n"
	"    <rule id=\"pin\" scope=\"public\">\n"
	"    <one-of>\n"
	"       <item>\n"
	"         <item repeat=\"0-1\"><ruleref uri=\"#digit\"/></item>\n"
	"           #\n"
	"         </item>"
	"       <item>"
	"         * 9 \n"
	"       </item>\n"
	"    </one-of>\n"
	"    </rule>\n"
	"</grammar>\n";

static const char *repeat_item_star_grammar =
	"<grammar mode=\"dtmf\" version=\"1.0\""
	"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	"    xsi:schemaLocation=\"http://www.w3.org/2001/06/grammar\n"
	"                        http://www.w3.org/TR/speech-grammar/grammar.xsd\""
	"    xmlns=\"http://www.w3.org/2001/06/grammar\">\n"
	"\n"
	"    <rule id=\"digit\">\n"
	"    <one-of>\n"
	"       <item> 0 </item>\n"
	"       <item> 1 </item>\n"
	"       <item> 2 </item>\n"
	"       <item> 3 </item>\n"
	"       <item> 4 </item>\n"
	"       <item> 5 </item>\n"
	"       <item> 6 </item>\n"
	"       <item> 7 </item>\n"
	"       <item> 8 </item>\n"
	"       <item> 9 </item>\n"
	"    </one-of>\n"
	"    </rule>\n"
	"\n"
	"    <rule id=\"pin\" scope=\"public\">\n"
	"    <one-of>\n"
	"       <item>\n"
	"         <item repeat=\"0-\"><ruleref uri=\"#digit\"/></item>\n"
	"           #\n"
	"         </item>"
	"       <item>"
	"         * 9 \n"
	"       </item>\n"
	"    </one-of>\n"
	"    </rule>\n"
	"</grammar>\n";

static const char *repeat_item_plus_grammar =
	"<grammar mode=\"dtmf\" version=\"1.0\""
	"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	"    xsi:schemaLocation=\"http://www.w3.org/2001/06/grammar\n"
	"                        http://www.w3.org/TR/speech-grammar/grammar.xsd\""
	"    xmlns=\"http://www.w3.org/2001/06/grammar\">\n"
	"\n"
	"    <rule id=\"digit\">\n"
	"    <one-of>\n"
	"       <item> 0 </item>\n"
	"       <item> 1 </item>\n"
	"       <item> 2 </item>\n"
	"       <item> 3 </item>\n"
	"       <item> 4 </item>\n"
	"       <item> 5 </item>\n"
	"       <item> 6 </item>\n"
	"       <item> 7 </item>\n"
	"       <item> 8 </item>\n"
	"       <item> 9 </item>\n"
	"    </one-of>\n"
	"    </rule>\n"
	"\n"
	"    <rule id=\"pin\" scope=\"public\">\n"
	"    <one-of>\n"
	"       <item>\n"
	"         <item repeat=\"1-\"><ruleref uri=\"#digit\"/></item>\n"
	"           #\n"
	"         </item>"
	"       <item>"
	"         * 9 \n"
	"       </item>\n"
	"    </one-of>\n"
	"    </rule>\n"
	"</grammar>\n";

static void test_repeat_item_grammar(void)
{
	struct srgs_parser *parser;

	parser = srgs_parser_new("1234");
	ASSERT_EQUALS(0, srgs_parse(parser, repeat_item_grammar_bad));
	ASSERT_EQUALS(0, srgs_parse(parser, repeat_item_grammar_bad2));
	ASSERT_EQUALS(0, srgs_parse(parser, repeat_item_grammar_bad3));
	ASSERT_EQUALS(0, srgs_parse(parser, repeat_item_grammar_bad4));
	ASSERT_EQUALS(0, srgs_parse(parser, repeat_item_grammar_bad5));
	ASSERT_EQUALS(0, srgs_parse(parser, repeat_item_grammar_bad6));
	ASSERT_EQUALS(1, srgs_parse(parser, repeat_item_grammar));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "1111#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "1111"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "1234#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "1234"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "11115#"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "11115"));
	ASSERT_EQUALS(1, srgs_parse(parser, repeat_item_range_grammar));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "1111#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "1111"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "1234#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "1234"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "11115#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "11115"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "111156#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "111156"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "1111567#"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "1111567"));
	ASSERT_EQUALS(1, srgs_parse(parser, repeat_item_optional_grammar));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "1111#"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "1111"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "1234#"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "1234"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "11115#"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "11115"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "111156#"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "111156"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "1111567#"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "1111567"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "1#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "1"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "#"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, ""));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "A#"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "A"));
	ASSERT_EQUALS(1, srgs_parse(parser, repeat_item_plus_grammar));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "1111#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "1111"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "1234#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "1234"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "11115#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "11115"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "111156#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "111156"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "111157#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "111157"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "1#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "1"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "#"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, ""));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "A#"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "A"));
	ASSERT_EQUALS(1, srgs_parse(parser, repeat_item_star_grammar));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "1111#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "1111"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "1234#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "1234"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "11115#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "11115"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "111156#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "111156"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "111157#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "111157"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "1#"));
	ASSERT_EQUALS(SMT_MATCH_PARTIAL, srgs_match(parser, "1"));
	ASSERT_EQUALS(SMT_MATCH, srgs_match(parser, "#"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, ""));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "A#"));
	ASSERT_EQUALS(SMT_NO_MATCH, srgs_match(parser, "A"));

	srgs_parser_destroy(parser);
}

/*
<polite> = please | kindly | oh mighty computer;
public <command> = [ <polite> ] don't crash;
*/
static const char *voice_srgs1 =
	"<grammar mode=\"voice\" version=\"1.0\"\n"
	"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
	"    xsi:schemaLocation=\"http://www.w3.org/2001/06/grammar\n"
	"                        http://www.w3.org/TR/speech-grammar/grammar.xsd\"\n"
	"    language\"en-US\"\n"
	"    xmlns=\"http://www.w3.org/2001/06/grammar\">\n"
	"\n"
	"    <rule id=\"polite\">\n"
	"    <one-of>\n"
	"      <item>please</item>\n"
	"      <item>kindly</item>\n"
	"      <item> oh mighty computer</item>\n"
	"    </one-of>\n"
	"    </rule>\n"
	"\n"
	"    <rule id=\"command\" scope=\"public\">\n"
	"       <item repeat=\"0-1\"><ruleref uri=\"#polite\"/></item>\n"
	"       <item>don't crash</item>\n"
	"    </rule>\n"
	"</grammar>\n";

static const char *voice_jsgf =
	"#JSGF V1.0;\n"
	"grammar org.freeswitch.srgs_to_jsgf;\n"
	"public <command> = [ <polite> ] don't crash;\n"
	"<polite> = ( please | kindly | oh mighty computer );\n";

static const char *rayo_test_srgs =
	"<grammar xmlns=\"http://www.w3.org/2001/06/grammar\" root=\"MAINRULE\">\n"
	"  <rule id=\"MAINRULE\">\n"
	"    <one-of>\n"
	"      <item>\n"
	"        <item repeat=\"0-1\"> need a</item>\n"
	"        <item repeat=\"0-1\"> i need a</item>\n"
	"        <one-of>\n"
	"          <item> clue </item>\n"
	"        </one-of>\n"
	"        <tag> out.concept = \"clue\";</tag>\n"
	"      </item>\n"
	"      <item>\n"
	"        <item repeat=\"0-1\"> have an</item>\n"
	"        <item repeat=\"0-1\"> i have an</item>\n"
	"        <one-of>\n"
	"          <item> answer </item>\n"
	"        </one-of>\n"
	"        <tag> out.concept = \"answer\";</tag>\n"
	"      </item>\n"
	"    </one-of>\n"
	"  </rule>\n"
	"</grammar>";

static void test_jsgf(void)
{
	struct srgs_parser *parser;
	const char *jsgf;
	parser = srgs_parser_new("1234");

	ASSERT_EQUALS(1, srgs_parse(parser, adhearsion_ask_grammar));
	ASSERT_NOT_NULL((jsgf = srgs_to_jsgf(parser)));
	ASSERT_EQUALS(1, srgs_parse(parser, voice_srgs1));
	ASSERT_NOT_NULL((jsgf = srgs_to_jsgf(parser)));
	ASSERT_STRING_EQUALS(voice_jsgf, jsgf);
	ASSERT_EQUALS(1, srgs_parse(parser, multi_rule_grammar));
	ASSERT_NOT_NULL((jsgf = srgs_to_jsgf(parser)));
	ASSERT_EQUALS(1, srgs_parse(parser, rayo_test_srgs));
	ASSERT_NOT_NULL((jsgf = srgs_to_jsgf(parser)));
	ASSERT_NULL(srgs_to_jsgf(NULL));
	srgs_parser_destroy(parser);
}

/**
 * main program
 */
int main(int argc, char **argv)
{
	const char *err;
	switch_core_init(0, SWITCH_TRUE, &err);
	TEST(test_parse_grammar);
	TEST(test_match_adhearsion_ask_grammar);
	TEST(test_match_multi_digit_grammar);
	TEST(test_match_multi_rule_grammar);
	TEST(test_match_rayo_example_grammar);
	TEST(test_repeat_item_grammar);
	TEST(test_jsgf);
	return 0;
}
