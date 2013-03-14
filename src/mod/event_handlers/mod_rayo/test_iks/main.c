

#include <switch.h>
#include <iksemel.h>


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

static const char *voxeo_grammar =
	"<iq id='8847' type='set' from='usera@192.168.1.10/voxeo3' to='e7632f74-8c55-11e2-84b0-e538fa88a1ef@192.168.1.10'><input xmlns='urn:xmpp:rayo:input:1' min-confidence='0.3' mode='DTMF' sensitivity='0.5'><grammar content-type='application/grammar+voxeo'><![CDATA[[1 DIGITS]]]></grammar></input></iq>";

static void test_iks_cdata_bug(void)
{
	iks *iq = NULL;
	iks *input = NULL;
	iksparser *p = iks_dom_new(&iq);
	const char *cdata;
	ASSERT_EQUALS(IKS_OK, iks_parse(p, voxeo_grammar, 0, 1));
	iks_parser_delete(p);
	ASSERT_NOT_NULL((input = iks_find(iq, "input")));
	ASSERT_NOT_NULL((cdata = iks_find_cdata(input, "grammar")));
	ASSERT_STRING_EQUALS("[1 DIGITS]", cdata);
	iks_delete(iq);
}

static const char *repeating_bracket =
	"<iq id='8847' type='set' from='usera@192.168.1.10/voxeo3' to='e7632f74-8c55-11e2-84b0-e538fa88a1ef@192.168.1.10'><input xmlns='urn:xmpp:rayo:input:1' min-confidence='0.3' mode='DTMF' sensitivity='0.5'><grammar content-type='application/grammar+voxeo'><![CDATA[[1 DIGITS]>]]]]]]]]] ]] ]]></grammar></input></iq>";

static void test_repeating_bracket(void)
{
	iks *iq = NULL;
	iks *input = NULL;
	iksparser *p = iks_dom_new(&iq);
	const char *cdata;
	ASSERT_EQUALS(IKS_OK, iks_parse(p, repeating_bracket, 0, 1));
	iks_parser_delete(p);
	ASSERT_NOT_NULL((input = iks_find(iq, "input")));
	ASSERT_NOT_NULL((cdata = iks_find_cdata(input, "grammar")));
	ASSERT_STRING_EQUALS("[1 DIGITS]>]]]]]]]]] ]] ", cdata);
	iks_delete(iq);
}

static const char *normal_cdata =
	"<iq id='8847' type='set' from='usera@192.168.1.10/voxeo3' to='e7632f74-8c55-11e2-84b0-e538fa88a1ef@192.168.1.10'><input xmlns='urn:xmpp:rayo:input:1' min-confidence='0.3' mode='DTMF' sensitivity='0.5'><grammar content-type='application/grammar+voxeo'><![CDATA[1 DIGITS]]></grammar></input></iq>";

static void test_normal_cdata(void)
{
	iks *iq = NULL;
	iks *input = NULL;
	iksparser *p = iks_dom_new(&iq);
	const char *cdata;
	ASSERT_EQUALS(IKS_OK, iks_parse(p, normal_cdata, 0, 1));
	iks_parser_delete(p);
	ASSERT_NOT_NULL((input = iks_find(iq, "input")));
	ASSERT_NOT_NULL((cdata = iks_find_cdata(input, "grammar")));
	ASSERT_STRING_EQUALS("1 DIGITS", cdata);
	iks_delete(iq);
}

static const char *empty_cdata =
	"<iq id='8847' type='set' from='usera@192.168.1.10/voxeo3' to='e7632f74-8c55-11e2-84b0-e538fa88a1ef@192.168.1.10'><input xmlns='urn:xmpp:rayo:input:1' min-confidence='0.3' mode='DTMF' sensitivity='0.5'><grammar content-type='application/grammar+voxeo'><![CDATA[]]></grammar></input></iq>";

static void test_empty_cdata(void)
{
	iks *iq = NULL;
	iks *input = NULL;
	iksparser *p = iks_dom_new(&iq);
	const char *cdata;
	ASSERT_EQUALS(IKS_OK, iks_parse(p, empty_cdata, 0, 1));
	iks_parser_delete(p);
	ASSERT_NOT_NULL((input = iks_find(iq, "input")));
	ASSERT_NULL((cdata = iks_find_cdata(input, "grammar")));
	iks_delete(iq);
}

/**
 * main program
 */
int main(int argc, char **argv)
{
	const char *err;
	switch_core_init(0, SWITCH_TRUE, &err);
	TEST(test_iks_cdata_bug);
	TEST(test_repeating_bracket);
	TEST(test_normal_cdata);
	TEST(test_empty_cdata);
	return 0;
}
