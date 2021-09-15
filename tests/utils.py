from pythf.client import Client
from pythf.const import Url


FAKE_API_TOKEN = "FAKE_TOKEN"
MALICIOUS_URL = "https://malicious-url.com"
ANALYSIS_ID = 43747305
COMMIT = "403a4300e5939d1d7fbfb90958aac5b413468ba3"
REPORT_ID = "9064747b9dc499a5d05611c51650e2f6da2003ec_ind1611854608"

ANALGIN_UPLOAD_ANSWER = {
    "data": {
        "ids": [ANALYSIS_ID]
    }
}

ATTACH_ANSWER = {
    "data": {
        "next": None,
        "previous": None,
        "results": [
            {
                "file_url": "/media/attach/manual/3e9e/3e9eecec9964cb43bcf38900cf3860f70eb0fb1c7887958f234b0e4c45a0abd7_yxYNH9I.\
                    url",
                "analgin_result": {
                    "error": None,
                    "commit": "403a4300e5939d1d7fbfb90958aac5b413468ba3",
                    "reports": [
                        {
                            "id": "9064747b9dc499a5d05611c51650e2f6da2003ec_ind1611854608",
                            "error": None,
                            "verdict": True
                        }
                    ],
                    "verdict": True,
                    "false_positive": False,
                    "context_desired": False
                },
                "src": "",
                "dst": "",
                "is_restorible": False,
                "appliance": 1,
                "company_name": "",
                "delay": 380.986531,
                "dst_ip": None,
                "envelope": None,
                "false_positive": False,
                "file_size": 103,
                "host": "tsarbox.ru.tds",
                "id": 43747305,
                "is_blocked": False,
                "is_deleted": False,
                "is_whitelisted": False,
                "md5": "f3c771ce41b8210b5dcb93f8795e1dc5",
                "meta": {
                    "url": "https://malicious-url.com",
                    "analgin": {
                        "error": None,
                        "commit": "403a4300e5939d1d7fbfb90958aac5b413468ba3",
                        "reports": [
                            {
                                "id": "9064747b9dc499a5d05611c51650e2f6da2003ec_ind1611854608",
                                "error": None,
                                "verdict": True
                            }
                        ],
                        "verdict": True,
                        "false_positive": False,
                        "context_desired": False
                    }
                },
                "msp_id": None,
                "on_hold": None,
                "src_ip": None,
                "original_filename": "some-name",
                "resolved": False,
                "sandbox_url": None,
                "sandbox_version": None,
                "search_id": "43747305",
                "sensor": "Group-IB HUNTBOX",
                "sha1": "9064747b9dc499a5d05611c51650e2f6da2003ec",
                "sha256": "3e9eecec9964cb43bcf38900cf3860f70eb0fb1c7887958f234b0e4c45a0abd7",
                "source": "MANUAL",
                "ts_analized": "2021-01-28T20:24:34.761642+03:00",
                "ts_created": "2021-01-28T20:18:13.775111+03:00",
                "ts_last_sync": None,
                "uploader": "Unknown",
                "verdict": True
            }
        ],
        "settings": None
    },
    "errors": [],
    "messages": []
}


SHORT_INFO = {
    "id": ANALYSIS_ID,
    "status": "FINISHED",
    "verdict": True,
    "report_url": "https://huntbox.group-ib.com/api/attaches/{}/{}/{}/polygon_report/".format(ANALYSIS_ID, COMMIT, REPORT_ID)
}

REPORT_ANSWER = {
    "data": {
        "info": {}
    }
}

REPORT = {
    "info": {}
}

EXPORTED_REPORT = b"report"
EXPORTED_PCAP = b"pcap"
EXPORTED_VIDEO = b"video"

HASH_TYPE = "md5"
HASH = "ablsahdblsdfhsieufhiwecn"
HASH_REPUTATION = {
    "found": True,
    "verdict": False,
    "score": 6.3,
    "malware_families": []
}

HASH_REPUTATION_ANSWER = {
    "data": {
        "found": True,
        "verdict": False,
        "score": 6.3,
        "malware_families": []
    }
}


class MockedClient(Client):
    def __init__(self):
        pass

    def _http_request(self, method, url_suffix, params=None, data=None, files=None, decode=True):
        FILE_INFO = ATTACH_ANSWER["data"]["results"][0]
        if url_suffix == Url.ANALGIN_UPLOAD:
            return ANALGIN_UPLOAD_ANSWER
        elif url_suffix == Url.ATTACH.format(ANALYSIS_ID):
            return ATTACH_ANSWER
        elif url_suffix == self._get_url(Url.REPORT, ANALYSIS_ID, FILE_INFO):
            return REPORT_ANSWER
        elif url_suffix == self._get_url(Url.EXPORT_REPORT, ANALYSIS_ID, FILE_INFO):
            return EXPORTED_REPORT
        elif url_suffix == self._get_url(Url.EXPORT_PCAP, ANALYSIS_ID, FILE_INFO):
            return EXPORTED_PCAP
        elif url_suffix == self._get_url(Url.EXPORT_VIDEO, ANALYSIS_ID, FILE_INFO):
            return EXPORTED_VIDEO
        elif url_suffix == Url.HASH_REPUTATION.format(HASH_TYPE, HASH):
            return HASH_REPUTATION_ANSWER
