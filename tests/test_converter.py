import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from convert import convert_line, convert_list, make_remote_snippet, parse_template, ConversionError, RuleSource


class ConverterTests(unittest.TestCase):
    def test_common_domains(self):
        self.assertEqual(convert_line('DOMAIN,chatgpt.com', 't', 1)[0], 'host, chatgpt.com')
        self.assertEqual(convert_line('DOMAIN-SUFFIX,openai.com', 't', 1)[0], 'host-suffix, openai.com')
        self.assertEqual(convert_line('DOMAIN-KEYWORD,claude', 't', 1)[0], 'host-keyword, claude')

    def test_wildcards_from_previous_errors(self):
        self.assertEqual(convert_line('DOMAIN-SUFFIX,*.tokenplus.app', 't', 1)[0], 'host-wildcard, *.tokenplus.app')
        self.assertEqual(convert_line('DOMAIN-SUFFIX,*2.bahamut.com.tw', 't', 1)[0], 'host-wildcard, *2.bahamut.com.tw')
        self.assertNotIn('host-suffix, *', convert_line('DOMAIN-SUFFIX,*2.bahamut.com.tw', 't', 1)[0])

    def test_ip_cidr_with_no_resolve(self):
        rule, warning = convert_line('IP-CIDR,8.8.8.0/24,no-resolve', 't', 1)
        self.assertEqual(rule, 'ip-cidr, 8.8.8.0/24')
        self.assertIn('no-resolve', warning)

    def test_ipv6(self):
        self.assertEqual(convert_line('IP-CIDR6,2001:4860::/32', 't', 1)[0], 'ip6-cidr, 2001:4860::/32')

    def test_reject_unknown_rule_and_modifiers(self):
        for text in ('UNEXPECTED-NEW-RULE,foo', 'DOMAIN-SUFFIX,a.com,proxy', 'DOMAIN-SUFFIX,a.com,unknown-option', 'DOMAIN,abc/com'):
            with self.subTest(text=text), self.assertRaises(ConversionError):
                convert_line(text, 't', 1)

    def test_skip_clash_only_process_rules_without_discarding_domains(self):
        source = "# OneDrive\nPROCESS-NAME,OneDrive\nPROCESS-NAME,OneDriveUpdater\nDOMAIN-KEYWORD,onedrive\nDOMAIN-SUFFIX,onedrive.com\n"
        rules, warnings = convert_list(source, 'OneDrive.list')
        self.assertEqual(rules, ['host-keyword, onedrive', 'host-suffix, onedrive.com'])
        self.assertEqual(len(warnings), 2)
        self.assertTrue(all('SKIPPED PROCESS-NAME' in warning for warning in warnings))
        self.assertIn('OneDrive.list:2', warnings[0])

    def test_skip_url_regex_but_keep_other_rules(self):
        source = 'DOMAIN-KEYWORD,aria2\nURL-REGEX,(torrent|announce.php?passkey=|tracker)\nDOMAIN-SUFFIX,smtp\n'
        rules, warnings = convert_list(source, 'Download.list')
        self.assertEqual(rules, ['host-keyword, aria2', 'host-suffix, smtp'])
        self.assertEqual(len(warnings), 1)
        self.assertIn('SKIPPED URL-REGEX', warnings[0])

    def test_no_compatible_rules_must_fail(self):
        with self.assertRaises(ConversionError):
            convert_list('PROCESS-NAME,OneDrive\n', 'only-process.list')

    def test_user_agent_supported(self):
        self.assertEqual(convert_line('USER-AGENT,OneDrive*', 't', 1)[0], 'user-agent, OneDrive*')

    def test_simple_list(self):
        rules, warnings = convert_list('# ignore\nDOMAIN,example.com\nIP-CIDR,1.1.1.0/24,no-resolve\n', 'mock')
        self.assertEqual(len(rules), 2)
        self.assertEqual(len(warnings), 1)

    def test_parse_template(self):
        lines = ['[custom]'] + [f'ruleset=AI,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Test{i}.list' for i in range(25)]
        lines += ['ruleset=Direct,[]GEOIP,CN', 'ruleset=Final,[]FINAL']
        sources, geo, final = parse_template('\n'.join(lines))
        self.assertEqual(len(sources), 25)
        self.assertTrue(geo and final)

    def test_policy_snippet_order(self):
        sources = [RuleSource('💬 Ai平台', 'u', Path('Ruleset/AI.list'))]
        snippet = make_remote_snippet(sources, 'alice/ACL4SSR-QuantumultX', 'main')
        self.assertIn('Rules/Ruleset/AI.list', snippet)
        self.assertIn('force-policy=💬 Ai平台', snippet)
        self.assertIn('FILTER_REGION', snippet)


if __name__ == '__main__':
    unittest.main()
