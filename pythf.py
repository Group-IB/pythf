import os

from client import Client
from const import THF_API_KEY, THF_API_URL, THF_VERIFY_SSL, \
    THF_CONNECTION_TIMEOUT, THF_PROXIES, THF_CONNECTION_RETRIES, \
    THF_USER_AGENT, DEFAULTS, __version__
from const import Language, Resolution, OpSystem, Capacity, Status
from error import ApiError, ObjectNotFoundError


class Polygon:
    def __init__(self, api_key=None, api_url=None, verify_ssl=None,
                       timeout=None, proxies=None, retries=None,
                       user_agent=None):
        """
        Create a Group-IB THF Polygon object.

        Parameters:
            api_key:    Group-IB THF API Key
            api_url:    Group-IB THF API URL
                        (default is https://huntbox.group-ib.com/)
            verify_ssl: Enable or disable checking SSL certificates
            timeout:    Timeout in seconds for accessing the API.
                        Raises a ConnectionError on timeout
            proxies:    Proxy settings
            retries:    Number of times requests should be retried
                        if they timeout
            user_agent: The user agent. Use this when you write an integration
                        with Group-IB THF so that it is possible to track
                        how often an integration is being used
        """
        self.client = Client(
            api_key=self._get_parameter(THF_API_KEY, api_key),
            base_url=self._get_parameter(THF_API_URL, api_url),
            verify_ssl=self._get_parameter(THF_VERIFY_SSL, verify_ssl),
            timeout=self._get_parameter(THF_CONNECTION_TIMEOUT, timeout),
            proxies=self._get_parameter(THF_PROXIES, proxies),
            retries=self._get_parameter(THF_CONNECTION_RETRIES, retries),
            user_agent=self._get_parameter(THF_USER_AGENT, user_agent)
        )
    
    def _get_parameter(self, name, value):
        """
            Get parameters for Polygon initialization.
            Use value if it is not 'None' else try to get it from environment.
            If there is no environment variable then use default.
        """
        if value is not None:
            if name == THF_USER_AGENT:
                return value + " ({})".format(DEFAULTS[name])
            return value
        if name not in os.environ:
            if name == THF_API_KEY:
                raise ApiError("No API key provided")
            return DEFAULTS[name]
        return os.environ.get(name)

    def ping(self):
        """
            Check if Group-IB THF server is online.
            Returns "OK" if all is good else raises ClientError.
        """
        return self.client.ping()

    def upload_file(self, file_obj, file_name="undefined.txt", password="",
                          language=Language.EN, mp=False,
                          timeout=180, resolution=Resolution.r1280x1024,
                          op_system=OpSystem.WIN_10, capacity=Capacity.x64):
        """
            Detonate file in THF Polygon.

            Parameters:
                file_obj:     The sample to detonate. Must be a file-like object
                              e.g. open('foo.bar') or BytesIO instance
                file_name:    The file name
                password:     The archive password
                language:     The report language (EN, RU)
                mp:           Try to use the MITM (Man in the middle) attack
                              while the detonation
                timeout:      Detonation timeout
                resolution:   The screen resolution
                op_system:    The system of VM (Windows XP, 7, 10)
                capacity:     VM capacity (x86 or x64)
            
            Returns an 'Analysis' object
        """
        return FileAnalysis(
            file_obj=file_obj,
            file_name=file_name,
            client=self.client,
            password=password,
            language=language,
            mp=mp,
            timeout=timeout,
            resolution=resolution,
            op_system=op_system,
            capacity=capacity
        )
    
    def upload_url(self, url, password="", language=Language.EN, mp=False,
                         timeout=180, resolution=Resolution.r1280x1024,
                         op_system=OpSystem.WIN_10, capacity=Capacity.x64):
        """
            Detonate URL in THF Polygon.

            Parameters:
                url:          The URL to detonate
                password:     The archive password
                language:     The report language (EN, RU)
                mp:           Try to use the MITM (Man in the middle) attack
                              while the detonation
                timeout:      Detonation timeout
                resolution:   The screen resolution
                op_system:    The system of VM (Windows XP, 7, 10)
                capacity:     VM capacity (x86 or x64)
            
            Returns an 'Analysis' object
        """
        return LinkAnalysis(
            url=url,
            client=self.client,
            password=password,
            language=language,
            mp=mp,
            timeout=timeout,
            resolution=resolution,
            op_system=op_system,
            capacity=capacity
        )
    
    def get_hash_reputation(self, hash_type, hash):
        """
            Get the hash reputation.

            Parameters:
                hash_type:   The hash type (md5, sha1, sha256)
                hash:        The hash to check
            
            Returns a dict object e.g.:
                {
                    "found": true | false,
                    "verdict": true | false,
                    "malware_families": [],
                    "score": float in [0; 100]
                }
        """
        return self.client.get_hash_reputation(hash_type, hash)


class Analysis:
    def __init__(self, client, password, language, mp, timeout,
                       resolution, op_system, capacity):
        """
            Create an Analysis object.
        """
        self.id = None
        self.client = client
        self.password = password
        self.language = language
        self.mp = mp
        self.timeout = timeout
        self.resolution = resolution
        self.op_system = op_system
        self.capacity = capacity
        self.status = None
        self.verdict = None
        self.report = None
        self.error = None
        self._run()

    def _run(self):
        self.status = Status.IN_PROGRESS
    
    def _update_status(self):
        try:
            analysis_info = self.client.get_analysis_info(self.id)
        except ApiError as err:
            self.status = Status.FAILED
            self.error = str(err)
            return {}
        if "report" in analysis_info:
            self.status = Status.FINISHED
            self.verdict = analysis_info.get("verdict")
            self.report = analysis_info.get("report")
        else:
            self.status = Status.IN_PROGRESS
        return analysis_info
    
    def _get_report_info(self):
        if not self.report:
            raise ObjectNotFoundError("Report not found")
        hr_verdict = "Malicious" if self.report["info"]["verdict"] else "Benign"
        hr_internet = "Available" if self.report["info"]["internet_available"] else "Unavailable"
        res = {
            "human_readable_verdict": hr_verdict,
            "started": self.report["info"]["started"],
            "finished": self.report["info"]["ended"],
            "internet-connection": hr_internet,
        }
        if self.report['info']['verdict']:
            res.update({
                "probability": "{:.2f}%".format(self.report["info"]["probability"]),
                "families": ", ".join(self.report["info"]["families"]),
                "score": self.report["info"]["score"],
                "dump_exists": any(map(lambda vals: len(vals) > 0, self.report["network"].values()))
            })
        return res

    @property
    def _info(self):
        return {
            "password": self.password,
            "language": self.language,
            "mitm": self.mp,
            "timeout": self.timeout,
            "resolution": self.resolution,
            "system": self.op_system,
            "capacity": self.capacity,
        }

    def get_info(self, extended=True):
        """
            Get the analysis info.
            You need to call this method to update the anlysis status.

            Parameters:
                extended:    Short or extended info
        """
        if self.status == Status.IN_PROGRESS:
            self._update_status()
        info = {
            "id": self.id,
            "status": self.status,
            "verdict": self.verdict
        }
        if self.status == Status.FAILED:
            info.update({
                "error": self.error
            })
        if extended:
            info.update(self._info)
            if self.status == Status.FINISHED:
                info.update(self._get_report_info())
        return info

    def get_report(self):
        """
            Get the detonation report.
        """
        return self.report

    def export_report(self):
        """
            Export the detonation report as .tar
            If the report is not ready ObjectNotFoundError will be raised.
        """
        return self.client.export_report(self.id)
    
    def export_pcap(self):
        """
            Export .pcap file with network activity.
            If there is no .pcap file ObjectNotFoundError will be raised.
        """
        return self.client.export_pcap(self.id)
    
    def export_video(self):
        """
            Export the screen-video of the detonation process.
            If there is no video ObjectNotFoundError will be raised.
        """
        return self.client.export_video(self.id)


class FileAnalysis(Analysis):
    def __init__(self, file_obj, file_name="undefined", **kwargs):
        self.file_obj = file_obj
        self.file_name = file_name
        self.original_filename = None
        self.size = None
        self.md5 = None
        self.sha1 = None
        self.sha256 = None
        super().__init__(**kwargs)

    def _run(self):
        self.id = self.client.upload_file(
            file_name=self.file_name,
            file_obj=self.file_obj,
            password=self.password,
            language=self.language,
            mp=self.mp,
            timeout=self.timeout,
            resolution=self.resolution,
            op_system=self.op_system,
            capacity=self.capacity
        )
        super()._run()
    
    def _update_status(self):
        analysis_info = super()._update_status()
        self.original_filename = self.original_filename or \
            analysis_info.get('original_filename')
        self.size = self.size or analysis_info.get("file_size")
        self.md5 = self.md5 or analysis_info.get('md5')
        self.sha1 = self.sha1 or analysis_info.get('sha1')
        self.sha256 = self.sha256 or analysis_info.get('sha256')
    
    def _get_report_info(self):
        res = {
            "type": self.report["target"]["file"]["type"]
        }
        res.update(super()._get_report_info())
        return res
    
    @property
    def _info(self):
        specific_info = {
            "filename": self.file_name,
            "original_filename": self.original_filename,
            "size": self.size,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256
        }
        specific_info.update(super()._info)
        return specific_info


class LinkAnalysis(Analysis):
    def __init__(self, url, **kwargs):
        self.url = url
        super().__init__(**kwargs)

    def _run(self):
        self.id = self.client.upload_link(
            link=self.url,
            password=self.password,
            language=self.language,
            mp=self.mp,
            timeout=self.timeout,
            resolution=self.resolution,
            op_system=self.op_system,
            capacity=self.capacity
        )
        super()._run()

    def _update_status(self):
        _ = super()._update_status()

    def _get_report_info(self):
        return super()._get_report_info()
    
    @property
    def _info(self):
        return super()._info
