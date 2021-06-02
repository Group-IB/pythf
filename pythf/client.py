import os
import requests
from urllib.parse import urljoin

from .const import Url, Method
from .error import ApiError, ClientError, ServerError, AuthenticationError, \
    ServerIsBeingUpdatedError, BadRequestError, BadResponseError, \
    ObjectNotFoundError, ConnectionError

class Client:
    def __init__(self, api_key, base_url, verify_ssl, timeout,
                       proxies, retries, user_agent):
        self.api_key = api_key
        self.base_url = base_url
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.proxies = proxies
        self.retries = retries
        self.user_agent = user_agent
        self.headers = {
            'X-API-KEY': self.api_key,
            'user-agent': self.user_agent
        }

    def _resp_handle(self, uri, resp, decode=True):
        kwargs = {
            "uri": uri,
            "status_code": resp.status_code,
            "message": resp.text
        }
        if resp.status_code >= 500:
            raise ServerError(**kwargs)
        elif resp.status_code == 401:
            raise AuthenticationError(**kwargs)
        elif resp.status_code == 423:
            raise ServerIsBeingUpdatedError(**kwargs)
        elif resp.status_code == 400:
            try:
                kwargs["message"] = resp.json().get("messages", "")
            except Exception:
                pass
            raise BadRequestError(**kwargs)
        elif resp.status_code != 200:
            raise ClientError(**kwargs)
        if decode:
            try:
                return resp.json()
            except Exception:
                raise BadResponseError(**kwargs)
        return resp.content

    def _http_request(self, method, url_suffix, params=None,
                            data=None, files=None, decode=True):
        url = urljoin(self.base_url, url_suffix)
        retries = 0
        while True:
            try:
                resp = requests.request(
                    method,
                    url,
                    headers=self.headers,
                    verify=self.verify_ssl,
                    params=params,
                    data=data,
                    files=files,
                    proxies=self.proxies,
                    timeout=self.timeout
                )
            except Exception as err:
                if retries > self.retries:
                    raise ConnectionError(uri=url_suffix,
                                          status_code=None,
                                          message="Retries limit exceeded",
                                          original_exception=err)
                retries += 1
            else:
                break
        return self._resp_handle(url_suffix, resp, decode)

    def _check_report_available(self, file_info):
        if "analgin_result" in file_info:
            if file_info["analgin_result"].get("error"):
                raise ApiError(file_info["analgin_result"]["error"])
            if "commit" in file_info["analgin_result"]:
                if "reports" in file_info["analgin_result"]:
                    if len(file_info["analgin_result"]["reports"]):
                        if "id" in file_info["analgin_result"]["reports"][0]:
                            return True
        return False

    def _get_fid(self, resp):
        fids = resp["data"].get("ids", [])
        if not fids:
            raise ApiError("No file ID returned from THF")
        return fids[0]

    def ping(self):
        self._http_request(Method.GET, Url.ATTACHES)
        return "OK"

    def filter_data(self, data):
        filtered_data = {k: v for k, v in data.items() if v is not None}
        tags = list(filter(lambda x: x is not None, data["tags"]))
        if tags:
            filtered_data["tags"] = tags
        return filtered_data

    def upload_file(self, file_name, file_obj, password, language, mp,
                        timeout, resolution, op_system, capacity, context_file,
                        av, dns, vm_route, clock, priority, human, internet,
                        wl, arguments, fsmtp, no_validation, extract_strings):
        data = {
            "language": language,
            "context_file": context_file,
            "password": password,
            "mp": mp,
            "av": av,
            "dns": dns,
            "route": vm_route,
            "clock": clock,
            "priority": priority,
            "human": human,
            "wl": wl,
            "fsmtp": fsmtp,
            "no_validation": no_validation,
            "extract_strings": extract_strings,
            "internet": internet,
            "arguments": arguments,
            "timeout": timeout,
            "resolution": resolution,
            "tags": [op_system, capacity]
        }
        filtered_data = self.filter_data(data)

        resp = self._http_request(
            method=Method.POST,
            url_suffix=Url.ANALGIN_UPLOAD,
            files={'files': (file_name, file_obj)},
            data=filtered_data
        )
        return self._get_fid(resp)

    def upload_link(self, link, password, language, mp, timeout,
                        resolution, op_system, capacity, context_file,
                        av, dns, vm_route, clock, priority, human, internet,
                        wl, arguments, fsmtp, no_validation, extract_strings):
        data = {
            "link": link,
            "language": language,
            "context_file": context_file,
            "password": password,
            "mp": mp,
            "av": av,
            "dns": dns,
            "route": vm_route,
            "clock": clock,
            "priority": priority,
            "human": human,
            "wl": wl,
            "fsmtp": fsmtp,
            "no_validation": no_validation,
            "extract_strings": extract_strings,
            "internet": internet,
            "arguments": arguments,
            "timeout": timeout,
            "resolution": resolution,
            "tags": [op_system, capacity]
        }
        filtered_data = self.filter_data(data)

        resp = self._http_request(
            method=Method.POST,
            url_suffix=Url.ANALGIN_UPLOAD,
            data=filtered_data
        )
        return self._get_fid(resp)

    def get_attach(self, id=None):
        url = Url.ATTACH.format(id) if id else Url.ATTACHES
        resp = self._http_request(Method.GET, url)["data"]["results"]
        if id:
            try:
                resp = resp[0]
            except Exception:
                err_text = "Object with ID={} does not exist".format(id)
                raise ObjectNotFoundError(err_text)
        return resp

    def _get_url(self, url, analysis_id, file_info):
        return url.format(analysis_id,
                          file_info["analgin_result"]["commit"],
                          file_info["analgin_result"]["reports"][0]["id"])

    def get_analysis_info(self, analysis_id):
        resp = self.get_attach(analysis_id)
        if not self._check_report_available(resp):
            return resp
        try:
            report = self._http_request(
                Method.GET,
                self._get_url(Url.REPORT, analysis_id, resp))
            resp.update({'report': report['data']})
        except Exception:
            pass
        return resp

    def _export_artifact(self, url, analysis_id):
        file_info = self.get_attach(analysis_id)
        if not self._check_report_available(file_info):
            raise ObjectNotFoundError
        return self._http_request(
            method=Method.GET,
            url_suffix=self._get_url(url, analysis_id, file_info),
            decode=False
        )

    def export_report(self, analysis_id):
        try:
            return self._export_artifact(Url.EXPORT_REPORT, analysis_id)
        except ObjectNotFoundError:
            raise ObjectNotFoundError("Report not found")

    def export_pcap(self, analysis_id):
        try:
            return self._export_artifact(Url.EXPORT_PCAP, analysis_id)
        except ObjectNotFoundError:
            raise ObjectNotFoundError("Pcap File not found")

    def export_video(self, analysis_id):
        try:
            return self._export_artifact(Url.EXPORT_VIDEO, analysis_id)
        except ObjectNotFoundError:
            raise ObjectNotFoundError("Screen Video not found")

    def get_hash_reputation(self, hash_type, hash_value):
        return self._http_request(
            method=Method.GET,
            url_suffix=Url.HASH_REPUTATION.format(hash_type, hash_value)
        )["data"]
