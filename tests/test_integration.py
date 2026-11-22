import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import convert
from patch_conf import replace_remote


class IntegrationTests(unittest.TestCase):
    def test_no_partial_publish_on_download_failure(self):
        sources = [f'ruleset=🎯 全球直连,{convert.RAW_PREFIX}Example/Example{i}.list' for i in range(25)]
        template = '\n'.join(sources + ['ruleset=🎯 全球直连,[]GEOIP,CN', 'ruleset=🐟 漏网之鱼,[]FINAL'])
        def fake_fetch(url):
            if url == convert.TEMPLATE_URL:
                return template
            if url.endswith('Example12.list'):
                raise convert.ConversionError('Simulated upstream outage')
            return 'DOMAIN-SUFFIX,example.com\n' * 50
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'Rules').mkdir()
            (root / 'Rules' / 'previous.list').write_text('old valid rules', encoding='utf-8')
            with patch('convert.fetch_text', side_effect=fake_fetch):
                with self.assertRaises(convert.ConversionError):
                    convert.run(root, 'sample/acl4ssr-qx', 'main')
            self.assertTrue((root / 'Rules' / 'previous.list').exists())

    def test_full_mock_pipeline_and_local_profile_patch(self):
        sources = [f'ruleset=🎯 全球直连,{convert.RAW_PREFIX}Example/Example{i}.list' for i in range(25)]
        template = '\n'.join(sources + ['ruleset=🎯 全球直连,[]GEOIP,CN', 'ruleset=🐟 漏网之鱼,[]FINAL'])
        def fake_fetch(url):
            if url == convert.TEMPLATE_URL:
                return template
            return 'DOMAIN-SUFFIX,example.com\n' * 50
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch('convert.fetch_text', side_effect=fake_fetch):
                report = convert.run(root, 'sample/acl4ssr-qx', 'main')
            self.assertEqual(report['rules'], 1250)
            self.assertEqual(len(list((root / 'Rules').rglob('*.list'))), 25)
            snippet = (root / 'filter_remote.snippet').read_text()
            profile = '[policy]\nstatic=🎯 全球直连, direct\n\n[filter_remote]\nold-remote-rule\n\n[filter_local]\nfinal, 🐟 漏网之鱼\n'
            result = replace_remote(profile, snippet)
            self.assertNotIn('old-remote-rule', result)
            self.assertIn('[filter_local]\nfinal, 🐟 漏网之鱼', result)
            self.assertIn('Rules/Example/Example0.list', result)

if __name__ == '__main__':
    unittest.main()
