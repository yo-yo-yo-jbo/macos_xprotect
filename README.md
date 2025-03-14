# Introduction to macOS - XProtect
Continuing my blogpost series on intoruction to macOS, I've decided to dedicate a short blogpost to [XProtect](https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web).

## What is XProtect?
XProtect is Apple's built-in antivirus and malware signature system for macOS.  
It operates as part of the `XProtectService`, which scans applications and other executable content for known malware signatures.  
XProtect works in the background and is updated silently by Apple through the `XProtectRemediator` mechanism (more on that later).  
It has 3 primary functions:
- Signature-based detection – It scans files against a database of known malware signatures.
- Behavioral detection (XProtect Remediator) – Introduced in macOS Monterey, this allows XProtect to proactively scan for and remove malware based on suspicious behaviors rather than just static signatures.
- Real-time blocking – XProtect prevents execution of known malicious software before it can run.

## Traditional XProtect
The directory `/System/Library/CoreServices/XProtect.bundle` is the main bundle that contains the XProtect configuration and signature definitions.  
This is a read-only system directory and is updated silently by Apple via XProtect updates.  
Under it, we can find some files of interest.

### XProtect.plist
The file `/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist` stores malware signatures used by XProtect to detect known threats.  
It contains entries mapping malware families to specific detection rules, including hashes and filename patterns.  
This file is periodically updated by Apple, and tampering with it is prevented by [System Integrity Protection (SIP)](https://github.com/yo-yo-yo-jbo/macos_sip/).

### XProtect.meta.plist
The file `/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist` is a metadata file that defines additional rules for XProtect, including enforcement policies and versioning information.  
It specifies which macOS versions enforce certain XProtect rules and actions taken upon detection.

## XProtect Remediator
A new XProtect System application stored as `/Library/Apple/System/Library/CoreServices/XProtect.app` wad introduced in macOS Monterey, and is responsible for running `XProtect Remediator`.  
Unlike the traditional XProtect (which primarily used signature-based detection), XProtect Remediator actively scans and removes malware from infected systems.  
It runs as a background process and can automatically remove detected threats without user intervention.
The directory `/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Resources` contains emediation scripts and additional detection logic for active scanning.

## MRT
Some of you might have heard about `MRT (Malware Removal Tool)`.  
Stored in `/Library/Apple/System/Library/CoreServices/MRT.app`, MRT is another macOS security component that works alongside XProtect.  
It is responsible for removing malware that XProtect has detected and operates silently in the background.  
MRT is more aggressive than XProtect in eradicating detected threats and can remove malicious files even if they are currently running.
