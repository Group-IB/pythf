import os

from .client import Client
from .const import THF_API_KEY, THF_API_URL, THF_VERIFY_SSL, \
    THF_CONNECTION_TIMEOUT, THF_PROXIES, THF_CONNECTION_RETRIES, \
    THF_USER_AGENT, DEFAULTS
from .const import Status
from .error import ApiError, ObjectNotFoundError


class Polygon:
    def __init__(self, api_key=None, api_url=None, verify_ssl=None, timeout=None, proxies=None, retries=None, user_agent=None):
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

    def upload_file(self, file_obj, file_name=None, password=None, language=None, mp=None, timeout=None, resolution=None,
                    op_system=None, capacity=None, context_file=None, av=None, dns=None, vm_route=None, clock=None, priority=None,
                    human=None, wl=None, arguments=None, fsmtp=None, no_validation=None, extract_strings=None, internet=None):
        """
            Detonate file in THF Polygon.

            Parameters:
                file_obj:           The sample to detonate. Must be a file-like object
                                    e.g. open('foo.bar') or BytesIO instance
                file_name:          The file name
                context_file:       Text file which can contain passwords for sample. Must be a file-like object
                                    e.g. open('pswd.txt') or BytesIO instance
                password:           The archive password
                language:           The report language (EN, RU)
                mp:                 Try to use the MITM (Man in the middle) attack
                                    while the detonation
                av:                 Enables or disables antivirus on VM (0, 1)
                dns:                Custom dns-server
                vm_route:           Exit route for VM (mgmt, vpn)
                clock:              The time set on VM (ex. "2021-03-05 12:22:26")
                priority:           Task priority
                human:              Active emulation of user actions (0, 1)
                wl:                 Using whitelists to exclude trusted programs from the startup list (0, 1)
                arguments:          Program launch arguments
                fsmtp:              Enables SMTP server emulation to intercept sent emails (0, 1)
                no_validation:      Disables automatic validation of the analysis (0, 1)
                extract_strings:    Extract all strings from samples (0, 1)
                internet:           Disables or enables internet on VM (0, 1)
                timeout:            Detonation timeout
                resolution:         The screen resolution
                op_system:          The system of VM (Windows XP, 7, 10)
                capacity:           VM capacity (x86 or x64)
            
            Returns an 'Analysis' object
        """
        if not file_name:
            try:
                file_name = file_obj.name
            except AttributeError:
                file_name = "undefined.txt"

        return FileAnalysis(
            file_obj=file_obj,
            file_name=file_name,
            context_file=context_file,
            client=self.client,
            password=password,
            language=language,
            mp=mp,
            av=av,
            dns=dns,
            vm_route=vm_route,
            clock=clock,
            priority=priority,
            human=human,
            wl=wl,
            arguments=arguments,
            fsmtp=fsmtp,
            no_validation=no_validation,
            extract_strings=extract_strings,
            internet=internet,
            timeout=timeout,
            resolution=resolution,
            op_system=op_system,
            capacity=capacity
        )
    
    def upload_url(self, url, password=None, language=None, mp=None, timeout=None, resolution=None, op_system=None, capacity=None,
                   context_file=None, av=None, dns=None, vm_route=None, clock=None, priority=None, human=None, wl=None,
                   arguments=None, fsmtp=None, no_validation=None, extract_strings=None, internet=None):
        """
            Detonate URL in THF Polygon.

            Parameters:
                url:                The URL to detonate
                context_file:       Text file in bytes which can contain passwords for sample. Must be a file-like object
                                    e.g. open('pswd.txt') or BytesIO instance
                password:           The archive password
                language:           The report language (EN, RU)
                mp:                 Try to use the MITM (Man in the middle) attack
                                    while the detonation
                av:                 Enables or disables antivirus on VM (0, 1)
                dns:                Custom dns-server
                vm_route:           Exit route for VM (mgmt, vpn)
                clock:              The time set on VM (ex. "2021-03-05 12:22:26")
                priority:           Task priority
                human:              Active emulation of user actions (0, 1)
                wl:                 Using whitelists to exclude trusted programs from the startup list (0, 1)
                arguments:          Program launch arguments
                fsmtp:              Enables SMTP server emulation to intercept sent emails (0, 1)
                no_validation:      Disables automatic validation of the analysis (0, 1)
                extract_strings:    Extract all strings from samples (0, 1)
                internet:           Disables or enables internet on VM (0, 1)
                timeout:            Detonation timeout
                resolution:         The screen resolution
                op_system:          The system of VM (Windows XP, 7, 10)
                capacity:           VM capacity (x86 or x64)
            
            Returns an 'Analysis' object
        """
        return LinkAnalysis(
            url=url,
            context_file=context_file,
            client=self.client,
            password=password,
            language=language,
            mp=mp,
            av=av,
            dns=dns,
            vm_route=vm_route,
            clock=clock,
            priority=priority,
            human=human,
            wl=wl,
            arguments=arguments,
            fsmtp=fsmtp,
            no_validation=no_validation,
            extract_strings=extract_strings,
            internet=internet,
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
    def __init__(self, client, context_file, password, language, mp, timeout, av, dns, vm_route, clock, priority, human,
                 wl, arguments, fsmtp, no_validation, extract_strings, internet, resolution, op_system, capacity):
        """
            Create an Analysis object.
        """
        self.id = None
        self.client = client
        self.context_file = context_file
        self.password = password
        self.language = language
        self.mp = mp
        self.av = av
        self.dns = dns
        self.vm_route = vm_route
        self.clock = clock
        self.priority = priority
        self.human = human
        self.wl = wl
        self.arguments = arguments
        self.fsmtp = fsmtp
        self.no_validation = no_validation
        self.extract_strings = extract_strings
        self.internet = internet
        self.timeout = timeout
        self.resolution = resolution
        self.op_system = op_system
        self.capacity = capacity
        self.status = None
        self.verdict = None
        self.report = None
        self.error = None
        self.report_url = None
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
        self.report_url = self.report_url or analysis_info.get('report_url')
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
            "antivirus": self.av,
            "dns": self.dns,
            "route": self.vm_route,
            "clock": self.clock,
            "priority": self.priority,
            "human": self.human,
            "whitelist": self.wl,
            "fsmtp": self.fsmtp,
            "no_validation": self.no_validation,
            "extract_strings": self.extract_strings,
            "internet": self.internet,
            "arguments": self.arguments,
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
        if self.report_url:
            info.update({"report_url": self.report_url})
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
            context_file=self.context_file,
            password=self.password,
            language=self.language,
            mp=self.mp,
            av=self.av,
            dns=self.dns,
            vm_route=self.vm_route,
            clock=self.clock,
            priority=self.priority,
            human=self.human,
            wl=self.wl,
            arguments=self.arguments,
            fsmtp=self.fsmtp,
            no_validation=self.no_validation,
            extract_strings=self.extract_strings,
            internet=self.internet,
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
            context_file=self.context_file,
            password=self.password,
            language=self.language,
            mp=self.mp,
            av=self.av,
            dns=self.dns,
            vm_route=self.vm_route,
            clock=self.clock,
            priority=self.priority,
            human=self.human,
            wl=self.wl,
            arguments=self.arguments,
            fsmtp=self.fsmtp,
            no_validation=self.no_validation,
            extract_strings=self.extract_strings,
            internet=self.internet,
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
