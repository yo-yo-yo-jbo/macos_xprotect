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
The directory `/Library/Apple/System/Library/CoreServices/XProtect.bundle` is the main bundle that contains the XProtect configuration and signature definitions.  
This is a read-only system directory and is updated silently by Apple via XProtect updates.  
Under it, we can find some files of interest, all periodically updated by Apple and protected by [System Integrity Protection (SIP)](https://github.com/yo-yo-yo-jbo/macos_sip/).

### XProtect.plist
The file `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist` stores malware signatures used by XProtect to detect known threats.  
It contains entries mapping malware families to specific detection rules, including hashes and filename patterns.  
Here is an example of one malware family - [Bundalore](https://attack.mitre.org/software/S0482/):

```xml
<dict>
        <key>Description</key>
        <string>OSX.Bundlore.D</string>
        <key>LaunchServices</key>
        <dict>
                <key>LSItemContentType</key>
                <string>com.apple.application-bundle</string>
        </dict>
        <key>Matches</key>
        <array>
                <dict>
                        <key>MatchFile</key>
                        <dict>
                                <key>NSURLTypeIdentifierKey</key>
                                <string>com.apple.applescript.script</string>
                        </dict>
                        <key>MatchType</key>
                        <string>Match</string>
                        <key>Pattern</key>
                        <string>46617364554153</string>
                </dict>
                <dict>
                        <key>MatchFile</key>
                        <dict>
                                <key>NSURLTypeIdentifierKey</key>
                                <string>com.apple.applescript.script</string>
                        </dict>
                        <key>MatchType</key>
                        <string>Match</string>
                        <key>Pattern</key>
                        <string>20006500630068006F002000</string>
                </dict>
                <dict>
                        <key>MatchFile</key>
                        <dict>
                                <key>NSURLTypeIdentifierKey</key>
                                <string>com.apple.applescript.script</string>
                        </dict>
                        <key>MatchType</key>
                        <string>Match</string>
                        <key>Pattern</key>
                        <string>20007C0020006F00700065006E00730073006C00200065006E00630020002D006100650073002D003200350036002D0063006600620020002D007000610073007300200070006100730073003A</string>
                </dict>
                <dict>
                        <key>MatchFile</key>
                        <dict>
                                <key>NSURLTypeIdentifierKey</key>
                                <string>com.apple.applescript.script</string>
                        </dict>
                        <key>MatchType</key>
                        <string>Match</string>
                        <key>Pattern</key>
                        <string>002D00730061006C00740020002D00410020002D00610020002D00640020007C002000620061007300680020002D0073</string>
                </dict>
        </array>
</dict>
```

This is quite human-readable, the only noteworthy part is that the `string` argument in each match is hexadecimal-representation, e.g. `002D00730061006C00740020002D00410020002D00610020002D00640020007C002000620061007300680020002D0073` corresponds to `-salt -A -a -d | bash -s`.  
This is, of course, a goldmine for malware authors, that know exactly which patterns to avoid.

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
