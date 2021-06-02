from io import BytesIO
from unittest import TestCase
from pythf import Polygon
from tests.utils import MockedClient, FAKE_API_TOKEN, MALICIOUS_URL, \
    ANALYSIS_ID, SHORT_INFO, REPORT, EXPORTED_REPORT, EXPORTED_PCAP, \
    EXPORTED_VIDEO, HASH_TYPE, HASH, HASH_REPUTATION


class TestPolygon(TestCase):
    def setUp(self):
        self.polygon = Polygon(FAKE_API_TOKEN)
        self.polygon.client = MockedClient()
    
    def test_upload_file(self):
        f = BytesIO(MALICIOUS_URL.encode())
        a = self.polygon.upload_file(f)
        self.assertEqual(a.id, ANALYSIS_ID)
    
    def test_upload_url(self):
        analysis = self.polygon.upload_url(MALICIOUS_URL)
        self.assertEqual(analysis.id, ANALYSIS_ID)
    
    def test_get_info(self):
        analysis = self.polygon.upload_url(MALICIOUS_URL)
        info = analysis.get_info(extended=False)
        self.assertDictEqual(SHORT_INFO, info)
    
    def test_get_report(self):
        analysis = self.polygon.upload_url(MALICIOUS_URL)
        analysis.get_info(extended=False)
        report = analysis.get_report()
        self.assertDictEqual(report, REPORT)
    
    def test_export_report(self):
        analysis = self.polygon.upload_url(MALICIOUS_URL)
        analysis.get_info(extended=False)
        report = analysis.export_report()
        self.assertEqual(report, EXPORTED_REPORT)
    
    def test_export_pcap(self):
        analysis = self.polygon.upload_url(MALICIOUS_URL)
        analysis.get_info(extended=False)
        pcap = analysis.export_pcap()
        self.assertEqual(pcap, EXPORTED_PCAP)
    
    def test_export_video(self):
        analysis = self.polygon.upload_url(MALICIOUS_URL)
        analysis.get_info(extended=False)
        video = analysis.export_video()
        self.assertEqual(video, EXPORTED_VIDEO)

    def test_get_hash_reputation(self):
        r = self.polygon.get_hash_reputation(HASH_TYPE, HASH)
        self.assertDictEqual(r, HASH_REPUTATION)
