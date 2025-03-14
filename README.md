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
The file `/Library/Apple/System/Library/CoreServices/XProtect.bundle/XProtect.meta.plist` is a metadata file that defines additional rules for XProtect, including enforcement policies and versioning information.  
It specifies which macOS versions enforce certain XProtect rules and actions taken upon detection, as well as blacklists for plugins.  
Here is an example:

```xml
<key>JavaWebComponentVersionMinimum</key>
<string>1.6.0_45-b06-451</string>
<key>PlugInBlacklist</key>
<dict>
        <key>10</key>
        <dict>
                <key>com.apple.java.JavaAppletPlugin</key>
                <dict>
                        <key>MinimumPlugInBundleVersion</key>
                        <string>14.8.0</string>
                        <key>PlugInUpdateAvailable</key>
                        <true/>
                </dict>
                <key>com.apple.java.JavaPlugin2_NPAPI</key>
                <dict>
                        <key>MinimumPlugInBundleVersion</key>
                        <string>14.8.0</string>
                        <key>PlugInUpdateAvailable</key>
                        <true/>
                </dict>
                <key>com.macromedia.Flash Player ESR.plugin</key>
                <dict>
                        <key>MinimumPlugInBundleVersion</key>
                        <string>18.0.0.382</string>
                        <key>PlugInUpdateAvailable</key>
                        <true/>
                </dict>
                <key>com.macromedia.Flash Player.plugin</key>
                <dict>
                        <key>MinimumPlugInBundleVersion</key>
                        <string>32.0.0.101</string>
                        <key>PlugInUpdateAvailable</key>
                        <true/>
                </dict>
                <key>com.microsoft.SilverlightPlugin</key>
                <dict>
                        <key>MinimumPlugInBundleVersion</key>
                        <string>5.1.41212.0</string>
                        <key>PlugInUpdateAvailable</key>
                        <true/>
                </dict>
                <key>com.oracle.java.JavaAppletPlugin</key>
                <dict>
                        <key>MinimumPlugInBundleVersion</key>
                        <string>1.8.51.16</string>
                        <key>PlugInUpdateAvailable</key>
                        <true/>
                </dict>
        </dict>
</dict>
```

As you can see, those contain version information for "blacklisted" plugins, for instance.

### XProtect.yara
In recent versions, XProtect seems to have started supporing [YARA](https://virustotal.github.io/yara/).  
The file `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara` contains several YARA rules in a text-format, here's a short example from it:

```yara
rule XProtect_MACOS_SLEEPYSTEGOSAURUS_SYM {
    meta:
        description = "MACOS.SLEEPYSTEGOSAURUS.SYM"
        uuid = "BB4F7D16-C939-4047-A9AF-E74E7B51FAC1"
    strings:
        $a1 = { 45 78 65 63 43 6D 64 }
        $a2 = { 47 65 74 48 6F 73 74 49 6E 66 6F }
        $a3 = { 52 75 6E 53 63 72 69 70 74 }
        $a4 = { 52 75 6E 53 63 72 69 70 74 55 72 6C }
        $a5 = { 4C 61 75 6E 63 68 50 6C 69 73 74 }
        $a6 = { 43 68 65 63 6B 50 72 6F 63 65 73 73 }
        $a7 = { 43 68 65 63 6B 49 6E }
        $a8 = { 52 75 6E 43 6D 64 46 69 6C 65 }
        $a9 = { 53 68 6F 77 48 74 6D 6C }
        $a10 = { 50 6C 69 73 74 48 65 6C 70 65 72 }
        $a11 = { 4C 61 75 6E 63 68 64 48 65 6C 70 65 72 }
        $a12 = { 43 6F 6D 6D 61 6E 64 46 69 6C 65 }
        $a13 = { 57 72 69 74 65 50 6C 69 73 74 }
        $a14 = { 4A 53 4F 4E 46 69 6C 65 50 72 6F 63 65 73 73 6F 72 }
        $a15 = { 43 68 72 6F 6D 65 48 65 6C 70 65 72 }
        $a16 = { 53 61 6E 64 62 6F 78 65 72 }
    condition:
        Macho and filesize < 2MB and all of them
}
```

This is not a blogpost about YARA rules, but as before - this is a gold mine for malware authors (e.g. `43 68 65 63 6B 50 72 6F 63 65 73 73` is `CheckProcess`).

### gk.db
Here you can see the integration between XProtect and [Gatekeeper](https://github.com/yo-yo-yo-jbo/macos_gatekeeper/).  
The file `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/gk.db` is a SQLite database containing a "blacklist" of file hashes and team IDs to block.  
You can view it with the `sqlite3` utility:

```
jbo@McJbo ~ $ sqlite3 "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/gk.db" .schema
CREATE TABLE settings (name TEXT, value TEXT, PRIMARY KEY (name));
CREATE TABLE blocked_hashes (hash BLOB, hash_type INTEGER, flags INTEGER, PRIMARY KEY (hash, hash_type));
CREATE TABLE blocked_teams (team_id TEXT, flags INTEGER, PRIMARY KEY (team_id));
jbo@McJbo ~ $ sqlite3 "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/gk.db" "SELECT * FROM blocked_teams LIMIT 5;"
F9X83Q5222|1
Q6XAB4776L|0
DK5C9Y86C8|0
8VK2WEPW22|0
5LWMEF3EX3|0
jbo@McJbo ~ $
```

This is again interesting information for malware authors, for example - to know when the Team ID they used to sign their malware with is on Apple's radar.

## XProtect Remediator
A new XProtect System application stored as `/Library/Apple/System/Library/CoreServices/XProtect.app` wad introduced in macOS Monterey, and is responsible for running `XProtect Remediator`.  
Unlike the traditional XProtect (which primarily used signature-based detection), XProtect Remediator actively scans and removes malware from infected systems.  
It runs as a background process and can automatically remove detected threats without user intervention.
The directory `/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Resources` contains emediation scripts and additional detection logic for active scanning.

### com.apple.XProtect.agent.scan.plist
The file `/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Resources/com.apple.XProtect.agent.scan.plist` contains settings about when to run periodic scans.  
For instance:

```xml
<key>com.apple.XProtect.PluginService.agent.slow.scan</key>
<dict>
        <key>Repeating</key>
        <true/>
        <key>PowerNap</key>
        <true/>
        <key>CPUIntensive</key>
        <true/>
        <key>DiskIntensive</key>
        <true/>
        <key>AllowBattery</key>
        <false/>
        <key>Priority</key>
        <string>Utility</string>
        <key>Interval</key>
        <integer>604800</integer>
</dict>
```

This shows certain performance conditions and even the scan's period (604800 seconds = once every 7 days).

## MRT
Some of you might have heard about `MRT (Malware Removal Tool)`.  
Stored in `/Library/Apple/System/Library/CoreServices/MRT.app`, MRT is another macOS security component that works alongside XProtect.  
It is responsible for removing malware that XProtect has detected and operates silently in the background.  
MRT is more aggressive than XProtect in eradicating detected threats and can remove malicious files even if they are currently running.  
Note that unlike `XProtect`, MRT does not maintain configuration files - everything is baked into the binary.  
Even looking at strings of the main binary (`/Library/Apple/System/Library/CoreServices/MRT.app/Contents/MacOS/MRT`) reveals interesting strings, e.g.:

```
import sys,base64;exec(base64.b64decode('
import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('
import sys;import re, subprocess;cmd = "ps -ef | grep Little\ Snitch | grep -v grep"
```

## How everything works together
When a file is downloaded via a browser or an application (e.g., Safari, Mail, Messages), it is marked with a quarantine flag (`com.apple.quarantine`) - I have already mentioned that flag in my [previous blogpost about Gatekeeper](https://github.com/yo-yo-yo-jbo/macos_gatekeeper/).  
Gatekeeper checks if the file is signed and notarized. If it is not, the user receives a warning before execution.  
If execution is allowed, XProtect scans the file against its known malware signatures (from `XProtect.plist`, `XProtect.yara` and so on).  
If malware is detected, the system prevents execution. If the malware is known and can be remediated, `XProtect Remediator` or `MRT` may delete or neutralize it.  
Apple updates `XProtect`, `MRT`, and `XProtect Remediator` silently in the background via the `XProtectService` process.
