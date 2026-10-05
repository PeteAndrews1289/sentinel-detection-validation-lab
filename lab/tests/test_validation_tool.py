import copy
import unittest
from tools.validate_run import validate_manifest, render_query, assess, missing_requirements

class ToolTests(unittest.TestCase):
    def setUp(self):
        self.m={'run_id':'abc123','case_id':'ps_positive','computer':'vm-dvl-win',
          'started_utc':'2026-09-30T12:00:00Z','ended_utc':'2026-09-30T12:00:10Z',
          'execution_ok':True,'cleanup_ok':True,'anchor':'harmless',
          'expected_rule_ids':['DVL-001'],
          'telemetry_requirements':[{'source_family':'Sysmon','event_id':1,'image_suffix':'\\powershell.exe'}]}
        self.raw=[{'SourceFamily':'Sysmon','EventID':1,'Image':'C:\\Windows\\powershell.exe'}]
        self.matches={'DVL-001':[{'EventKey':'key1'}]}
        self.alerts=[{'AlertName':'DVL-001 | Lab','SystemAlertId':'alert1','ExtendedProperties':'key1'}]
    def test_valid_manifest(self): validate_manifest(self.m)
    def test_wrong_expectations_rejected(self):
        self.m['expected_rule_ids']=[]
        with self.assertRaises(ValueError): validate_manifest(self.m)
    def test_naive_time_rejected(self):
        self.m['started_utc']='2026-09-30T12:00:00'
        with self.assertRaises(ValueError): validate_manifest(self.m)
    def test_reverse_window_rejected(self):
        self.m['ended_utc']='2026-09-30T11:00:00Z'
        with self.assertRaises(ValueError): validate_manifest(self.m)
    def test_no_raw_telemetry_is_not_pass(self):
        self.assertEqual(assess(self.m,[],self.matches,self.alerts)['status'],'MISSING_REQUIRED_TELEMETRY')
    def test_wrong_image_is_missing(self):
        self.assertTrue(missing_requirements([{'SourceFamily':'Sysmon','EventID':1,'Image':'notepad.exe'}],self.m['telemetry_requirements']))
    def test_execution_failure(self):
        self.m['execution_ok']=False
        self.assertEqual(assess(self.m,self.raw,self.matches,self.alerts)['status'],'EXECUTION_FAILED')
    def test_cleanup_failure(self):
        self.m['cleanup_ok']=False
        self.assertEqual(assess(self.m,self.raw,self.matches,self.alerts)['status'],'CLEANUP_FAILED')
    def test_query_mismatch(self):
        self.assertEqual(assess(self.m,self.raw,{},[])['status'],'QUERY_MISMATCH')
    def test_no_alert_is_pending(self):
        self.assertEqual(assess(self.m,self.raw,self.matches,[])['status'],'QUERY_PASS_ALERT_PENDING_OR_UNRESOLVED')
    def test_matched_alert(self):
        self.assertEqual(assess(self.m,self.raw,self.matches,self.alerts)['status'],'POSITIVE_QUERY_AND_ALERT_VALIDATED')
    def test_negative_still_needs_review(self):
        self.m['expected_rule_ids']=[]; self.m['case_id']='ps_negative'
        self.assertEqual(assess(self.m,self.raw,{},[])['status'],'NEGATIVE_QUERY_PASS_ALERT_REVIEW_REQUIRED')
    def test_duplicate_alert_ids_deduplicated(self):
        r=assess(self.m,self.raw,self.matches,self.alerts*2)
        self.assertEqual(r['event_key_to_alert_ids']['key1'],['alert1'])
    def test_wrong_rule_alert_does_not_match(self):
        self.alerts[0]['AlertName']='DVL-002 | Wrong rule'
        self.assertEqual(assess(self.m,self.raw,self.matches,self.alerts)['status'],'QUERY_PASS_ALERT_PENDING_OR_UNRESOLVED')
    def test_render_is_scoped_and_appends_anchor(self):
        text='// DVL PARAMETERS BEGIN\nold\n// DVL PARAMETERS END\nEvent'
        q=render_query(text,self.m)
        self.assertIn('datetime(2026-09-30T11:59:59Z)',q)
        self.assertIn('where Evidence contains "harmless"',q)
    def test_missing_parameter_block_rejected(self):
        with self.assertRaises(ValueError): render_query('Event',self.m)

if __name__=='__main__': unittest.main()
