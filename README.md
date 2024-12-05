# Security-Tools-II
Second part with more scripts oriented to cybersecurity and networking, any feedback is welcome to improve. All this has to be used for ethical purposes and in controlled environments.
<br><br><em><b>What this repository contains</b></em>
<br>
I will gradually add more scripts, for now:
<br>A DNS parser
<br>A malware detector in bin files
<br>A keylogger
<br>Enhanced hashes cracker
<br>File and directory permissions auditor
<br>Dictionary generator
<br>All scripts are accompanied by their dependencies and can be upgraded to a more powerful version at any time.


---------------------------------------
<b>A DNS parser</b>
<br>This script analyzes DNS traffic in real time and detects suspicious patterns, such as unusual queries or possible DNS tunneling attacks. This script should work correctly if TShark is installed and configured correctly on your system. Make sure TShark is in your PATH so that pyshark can find it.
  <ol>Filters A-type packets, CNAME, and unusual queries</ol>
  <ol>It generates alerts if it detects:</ol> <ol>Queries with long or repeated names</ol><ol>Queries to suspicious domains (blacklist).</ol>
<br>
<b>A malware detector in bin files</b>
<br>Analyzes binary files for suspicious patterns, known hashes or strings common in malware.
<ol>Basic scheme:</ol>
  <ol>Extract hashes (MD5, SHA256) from the file</ol>
  <ol>Compare with a malicious hashes database (such as VirusTotal API)</ol>
  <ol>Identify strings embedded in binaries</ol>
<br>
<b>A keylogger</b>
<br>It records keystrokes for educational or forensic analysis purposes.
  <ol>Using a keyboard monitoring library</ol>
  <ol>Save keystrokes to a file or send them to a controlled server</ol>
It can be made more advanced, I will update it to make it more powerful.
<br>
<b>Enhanced hashes cracker</b>
<br>Breaks hashes using dictionaries and supports various algorithms (MD5, SHA-256, bcrypt...)
  <ol>Load a target hash and a dictionary</ol>
  <ol>Compare hashes generated from the dictionary with the target</ol>
  <ol>Support for multiple algorithms</ol>
<br>
<b>File and directory permissions auditor</b>
<br>Scans the system for insecure permission settings
  <ol>Uses <em>os</em> to browse directories and obtain permissions</ol>
  <ol>Detects permissions as 777 and alerts the user</ol>
<br>
<b>Dictionary generator</b>
<br>Creates customized dictionaries based on user patterns (dates, names, keywords)
  <ol>Request basic information (names, dates, related words...)</ol>
  <ol>Combine patterns to generate combinations</ol>
  <ol>Save the dictionary to a file</ol>
