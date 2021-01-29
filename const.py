__version__ = "1.0.2"

THF_API_KEY = "THF_API_KEY"
THF_API_URL = "THF_API_URL"
THF_VERIFY_SSL = "THF_VERIFY_SSL"
THF_CONNECTION_RETRIES = "THF_CONNECTION_RETRIES"
THF_CONNECTION_TIMEOUT = "THF_CONNECTION_TIMEOUT"
THF_PROXIES = "THF_PROXIES"
THF_USER_AGENT = "THF_USER_AGENT"

DEFAULTS = {
    THF_API_URL: "https://huntbox.group-ib.com/",
    THF_VERIFY_SSL: True,
    THF_CONNECTION_RETRIES: 3,
    THF_CONNECTION_TIMEOUT: 10,
    THF_PROXIES: {},
    THF_USER_AGENT: "pythf v" + __version__
}


class Status:
    IN_PROGRESS = "IN PROGRESS"
    FINISHED = "FINISHED"
    FAILED = "FAILED"


class Language:
    RU = "ru"
    EN = "en"


class Resolution:
    r800x600 = "800x600"
    r1024x768 = "1024x768"
    r1152x1024 = "1152x1024"
    r1280x1024 = "1280x1024"
    r1600x1200 = "1600x1200"


class OpSystem:
    WIN_XP = "winxp"
    WIN_7 = "win7"
    WIN_10 = "w10"


class Capacity:
    x86 = "x86"
    x64 = "x64"


class Url:
    API = "api/"

    ANALGIN_UPLOAD = API + "analgin/upload/"

    ATTACHES = API + "attaches/"
    ATTACH = ATTACHES + "?id={}"

    REPORT = ATTACHES + "{}/{}/{}/polygon_report/"

    EXPORT_REPORT = ATTACHES + "{}/{}/{}/polygon_report_export/"
    EXPORT_PCAP = ATTACHES + '{}/{}/{}/dump.pcap/dump.pcap/polygon_report_file_download/'
    EXPORT_VIDEO = ATTACHES + '{}/{}/{}/shots/video.webm/video.webm/polygon_report_file_download/'
    
    HASH_REPUTATION = API + 'reports/check_hash/{}/{}/'


class Method:
    GET = 'GET'
    POST = 'POST'
