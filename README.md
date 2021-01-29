# Python bindings for Group-IB THF REST API

**Latest Version: 1.0.2**

## Description

The Group-IB THF Python Client enables you to fully integrate Group-IB THF Polygon into your malware analysis framework.
Group-IB THF Polygon is a Malware Detonation & Research platform designed for deep dynamic analysis and enhanced indicators extraction.

You can use this library with

 * [Group-IB THF Cloud](https://www.huntbox.group-ib.com) — our Cloud hosted instance
 * [On-premise installations of Group-IB THF](https://www.group-ib.com/threat-hunting-framework.html) — for even more power and privacy

 ## License

 The code is written in Python and licensed under MIT.

 ## Requirements

 * python 3.5 or higher

## Getting Started

### Installation

    pip install pythf

For upgrading `pythf` to a more recent version, use
    
    pip install --upgrade pythf

### API Key

In order to perform any queries via the API, you will need to get the API token for your Group-IB THF user.
1. Open Group-IB THF Huntbox web interface.
2. Navigate to "Profile" and click "Generate Auth Token".
3. Copy this token. This is your API Key.

### Sample Code

1. Let's start by sending some file ("sample.exe") for analysis:
```
from pythf import Polygon

polygon = Polygon("MY_API_KEY")
analysis = polygon.upload_file(open("sample.exe"))
```
2. If you want to detonate some URL, use the next method:
```
analysis = polygon.upload_url("https://very-malicious-url.com")
```
Now we have the `analysis` object.
To update analysis status and get info about it, use the next method:
```
info = analysis.get_info(extended=True)
```
**Notice**: parameter `extended` allows you to get full or short info about analysis process. The short version of the information is as follows:
```
{
    "status": "IN PROGRESS" | "FINISHED" | "FAILED",
    "verdict": None | True | False,
    "error": "Some error"  # optional field only for "FAILED" status
}
```
If the "verdict" is `True` then object is malicious.

3. You can get full report as a dictionary:
```
report = analysis.get_report()
```
4. There is a way to download some detonation artifacts and the report:
```
archived_report = analysis.export_report()  # Export report as .tar.
pcap = analysis.export_pcap()               # Export all network activity as .pcap file.
screen_video = analysis.export_video()      # Export the screen-video of the detonation process.
```

**Notice**: If there is no artifact, all this methods raise `ObjectNotFoundError`.

5. You can check some hash reputation with this method:
```
reputation = polygon.get_hash_reputation("md5", "ac55cf33c4691f863bfb3af8c06a7244")
```
You can get reputation for `md5`, `sha1`, `sha256` hash types.
The method returns a dict object:
```
{
    "found": true | false,
    "verdict": true | false,
    "malware_families": [],
    "score": float in [0; 100]
}
```
