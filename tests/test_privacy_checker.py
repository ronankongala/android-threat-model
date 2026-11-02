import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

import privacy_checker as pc  # noqa: E402


def apk(perms=(), components=(), decoded_dir=None):
    d = {'package': 'com.example', 'permissions': list(perms),
         'components': [{'name': n, 'type': 'activity'} for n in components]}
    if decoded_dir:
        d['decoded_dir'] = decoded_dir
    return d


def rules(findings):
    return [(f['rule'], f['severity']) for f in findings]


def test_location_claim_with_fine_location():
    f = pc.check('We do not collect your location.', apk(['android.permission.ACCESS_FINE_LOCATION']))
    assert rules(f) == [('location-not-collected', 'high')]
    assert 'ACCESS_FINE_LOCATION' in f[0]['evidence']


def test_location_claim_without_permission_is_clean():
    assert pc.check('We never track your location.', apk(['android.permission.INTERNET'])) == []


def test_coarse_location_is_medium():
    f = pc.check("The app doesn't access location data.", apk(['android.permission.ACCESS_COARSE_LOCATION']))
    assert rules(f) == [('location-not-collected', 'medium')]


def test_on_device_claim_with_internet():
    f = pc.check('All data stays on your device.', apk(['android.permission.INTERNET']))
    assert rules(f) == [('data-stays-on-device', 'medium')]


def test_on_device_claim_with_internet_and_sdk_is_high():
    f = pc.check('Your data never leaves your device.',
                 apk(['android.permission.INTERNET'], ['com.google.android.gms.ads.AdActivity']))
    assert ('data-stays-on-device', 'high') in rules(f)


def test_no_sharing_with_ad_sdk_in_manifest():
    f = pc.check('We do not share data with third parties.',
                 apk(components=['com.google.android.gms.ads.AdActivity']))
    assert rules(f) == [('no-third-party-sharing', 'high')]
    assert 'manifest' in f[0]['evidence']


def test_no_sharing_with_sdk_in_smali(tmp_path):
    os.makedirs(tmp_path / 'smali_classes2' / 'com' / 'mopub' / 'common')
    f = pc.check('Your data is not shared with any third party.', apk(decoded_dir=str(tmp_path)))
    assert rules(f) == [('no-third-party-sharing', 'high')]
    assert 'code' in f[0]['evidence']


def test_analytics_sdk_is_medium(tmp_path):
    os.makedirs(tmp_path / 'smali' / 'com' / 'google' / 'firebase' / 'analytics')
    f = pc.check('We will never sell or share your information with third parties.',
                 apk(decoded_dir=str(tmp_path)))
    assert rules(f) == [('no-third-party-sharing', 'medium')]


def test_positive_statement_is_not_a_claim():
    text = 'We collect your location to show nearby gyms. We share data with third parties.'
    assert pc.check(text, apk(['android.permission.ACCESS_FINE_LOCATION'],
                              ['com.google.android.gms.ads.AdActivity'])) == []


def test_markdown_section():
    lines = pc.to_markdown([], 'p.txt')
    assert lines[0] == '## Privacy Policy Analysis'
    assert 'No contradictions' in lines[-1]
    lines = pc.to_markdown(pc.check('We do not collect location.',
                                    apk(['android.permission.ACCESS_FINE_LOCATION'])))
    assert any(l.startswith('| high | location-not-collected') for l in lines)


def test_report_privacy_section(tmp_path):
    import json
    import report
    priv = pc.check('We do not collect location.', apk(['android.permission.ACCESS_FINE_LOCATION']))
    _, md = report.write([], 'x', str(tmp_path), None, privacy=priv, policy_name='p.txt')
    text = open(md, encoding='utf-8').read()
    assert '## Privacy Policy Analysis' in text and 'location-not-collected' in text
    data = json.load(open(tmp_path / 'x-privacy.json', encoding='utf-8'))
    assert data['policy'] == 'p.txt' and len(data['privacy']) == 1
    _, md = report.write([], 'y', str(tmp_path))
    assert 'Privacy Policy' not in open(md, encoding='utf-8').read()
    assert not (tmp_path / 'y-privacy.json').exists()


def test_cli_policy_flag():
    import ate
    args = ate.parse_args(['--apk', 'a.apk', '--policy', 'p.txt'])
    assert args.policy == 'p.txt'
    assert ate.main(['--apk', 'a.apk', '--policy', 'missing-policy.txt']) == 1


def test_3rd_party_spelling():
    f = pc.check('Your data is not shared with any 3rd parties.',
                 apk(components=['com.google.android.gms.ads.AdActivity']))
    assert rules(f) == [('no-third-party-sharing', 'high')]


def test_markdown_emphasis_claims():
    text = '* __No Internet access:__ Internet is not used\n* __No in-app analytics__\n'
    f = pc.check(text, apk(['android.permission.INTERNET'], ['com.google.android.gms.ads.AdActivity']))
    assert ('data-stays-on-device', 'high') in rules(f)
    assert ('no-third-party-sharing', 'high') in rules(f)
    assert 'ACCESS_FINE_LOCATION' in pc.sentences('* _ACCESS_FINE_LOCATION_: GPS')[0]
