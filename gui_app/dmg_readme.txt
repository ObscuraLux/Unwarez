ObscuraLux Unwarez v1.6.4 - Setup Guide
==========================================================

This app works right away with zero setup - every scan already runs
ReleaseSeal and CIRCL (both free databases, no signup) plus a built-in
list of 167 known-malicious hashes. Everything below is OPTIONAL, but
each piece genuinely strengthens what the app can catch. Read as much
or as little as you want - the app won't nag you either way.

macOS COMPATIBILITY
--------------------
This app (the .app in this DMG) requires macOS 12.0 Monterey (2021)
or later - it's a universal binary, so that applies equally on Intel
and Apple Silicon Macs. On an older Mac, the app itself won't open,
but the exact same detection engine is also available as a
Terminal-only tool with no such requirement: the CLI scripts (plain
bash, no compiled binary) run on essentially any macOS version,
including systems as old as 10.10 Yosemite. Ask wherever you got this
DMG for the CLI version if you're on an older Mac.


==========================================================
1. FIRST LAUNCH (required, one-time)
==========================================================

Since this app isn't signed with a paid Apple Developer certificate,
macOS will block it the first time you open it.

  Right-click "ObscuraLux Unwarez" in Applications -> Open
  -> confirm.

That's it. macOS remembers your choice after this.


==========================================================
2. FULL DISK ACCESS (recommended)
==========================================================

WHY: Without this, scans of your Desktop, Documents, Downloads, and
especially a full-system scan may silently skip files macOS is
protecting - you'd see a "clean" result that's actually incomplete,
not because nothing was found but because the app was never allowed
to look. This is the single most impactful thing on this list.

IMPORTANT: unlike the Terminal/CLI version of this tool, permission
goes to the APP ITSELF here, not to Terminal.

HOW TO ADD IT:
  1. Open System Settings
  2. Go to Privacy & Security -> Full Disk Access
  3. Click the + button
  4. Navigate to Applications and select "ObscuraLux Unwarez"
  5. Make sure the toggle next to it is switched on
  6. Quit and reopen the app for the change to take effect


==========================================================
3. VIRUSTOTAL - real-time hash lookups (optional, free)
==========================================================

WHY IT'S WORTH HAVING: VirusTotal aggregates results from 60-70+
antivirus engines at once for a given file hash. It's one of the most
comprehensive "has anyone, anywhere, ever flagged this file" checks
that exists, and it's free for personal use.

HOW TO GET A KEY:
  1. Go to virustotal.com and sign up (a normal account, no payment
     info needed)
  2. Once logged in, go to: https://www.virustotal.com/gui/my-apikey
  3. Copy the key shown there (should be exactly 64 characters)
  4. In the app: Settings -> paste into "VirusTotal API key" -> Save

Free-tier limits: 500 lookups/day, 4/minute. The app already paces
itself to stay under this automatically, so large scans just take a
bit longer rather than erroring out.

A NOTE ON PASTING: paste carefully. If a Save shows a yellow warning
that the key "doesn't look right," you likely copied something else
by accident (this has happened before - a chunk of Terminal output
got pasted in once instead of the actual key). Just re-copy and
re-paste if you see that warning.


==========================================================
4. MALWAREBAZAAR - malware-sample database (optional, free)
==========================================================

WHY IT'S WORTH HAVING: Run by abuse.ch, a well-known Swiss security
research group. Where VirusTotal tells you "have other antivirus
engines seen this," MalwareBazaar is specifically a database of
confirmed malware samples researchers have submitted - a different,
complementary source rather than a duplicate check.

HOW TO GET A KEY:
  1. Go to https://auth.abuse.ch/ and sign up (free account)
  2. Once logged in, find your Auth-Key on your account page
  3. In the app: Settings -> paste into "MalwareBazaar API key" -> Save


==========================================================
5. CLAMAV - real content scanning (optional, but the most
   meaningfully different addition on this list)
==========================================================

WHY THIS ONE MATTERS MORE THAN THE OTHERS: every other check in this
app - ReleaseSeal, VirusTotal, MalwareBazaar, the built-in threat
list - works by comparing file HASHES against databases of known-bad
files. That means they can only ever catch something that's byte-
for-byte identical to a file someone has already seen before. Change
a single byte of a malicious file - recompile it, repack it - and
every hash-based check in this app becomes blind to it.

ClamAV is different: it actually inspects file CONTENT (including
looking inside .zip archives), using signature and heuristic
detection rather than hash matching. It's the one piece of this app
that has a real chance of catching something genuinely new.

This requires two things: Homebrew (a package manager for macOS -
think of it as an app store for command-line tools) and then ClamAV
itself through it.

--- Step A: Install Homebrew (if you don't already have it) ---

Check first:
  which brew

If that prints nothing, install it:
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

This asks for your Mac's login password partway through (needed to
set up system directories) and takes a few minutes. When it finishes,
it prints some "Next steps" commands - run those too, they add
Homebrew to your PATH so the command actually works:
  echo >> ~/.zprofile
  echo 'eval "$(/opt/homebrew/bin/brew shellenv zsh)"' >> ~/.zprofile
  eval "$(/opt/homebrew/bin/brew shellenv zsh)"

--- Step B: Install ClamAV ---

  brew install clamav

Takes a couple of minutes, downloads about 100MB.

--- Step C: Set up its virus-definition database ---

  cp /opt/homebrew/etc/clamav/freshclam.conf.sample /opt/homebrew/etc/clamav/freshclam.conf
  sed -i '' '/^Example/d' /opt/homebrew/etc/clamav/freshclam.conf
  freshclam

This last command downloads the actual virus signatures (~100MB,
takes a few minutes). You may see lines saying "ERROR: NULL X509
store" during this - that's a known cosmetic quirk on fresh Homebrew
installs and does not mean it failed; check for "Database test
passed" and real signature counts in the output to confirm it
actually worked.

Once this is done, the app will automatically start using ClamAV on
every scan - no toggle or setting needed, it just detects that
clamscan is now available.


==========================================================
6. XCODE COMMAND LINE TOOLS - only if you want to MODIFY this
   app, not to run it
==========================================================

You do NOT need this to use the app from this DMG - it's already
compiled and ready to run. This is only relevant if you want to
change the Swift source code yourself and rebuild it (the source is
available separately, not part of this DMG). If that's ever of
interest:
  xcode-select --install

Otherwise, skip this section entirely - it has no bearing on using
the app normally.


==========================================================
7. RAR ARCHIVE SUPPORT (optional, free)
==========================================================

.rar files are now scanned like any other file type. Unlike .zip
(built into macOS by default), reading .rar files needs one small
extra tool. Note: the old standard tool for this, unrar, has been
removed from Homebrew - unar is the current, actively-maintained
replacement and is what this app uses.

  brew install unar

That's it - no further setup needed, no database to download. Once
installed, the app automatically detects it's available.


==========================================================
8. WHAT "DEEP INSPECTION" MEANS (automatic, no setup needed)
==========================================================

For .zip and .rar files specifically (and, less thoroughly tested,
.dmg and .pkg), this app doesn't just check the outer file's hash -
when nothing else has a verdict on a file, it looks INSIDE the
archive too. This matters because repackaging a known-malicious file
inside a new wrapper changes the outer file's hash completely, which
would otherwise let it slip past every hash-based check in this app.
This only ever adds to a MALICIOUS finding - it never marks something
extra as "verified clean," since a few safe files inside an archive
don't prove the whole archive is safe.



Scan runs using: ReleaseSeal + CIRCL + the built-in 167-hash list.
Files get one of four results:
  VERIFIED    - confirmed clean by a real database
  MALICIOUS   - matched a known-bad hash, auto-quarantined
  PUP         - Potentially Unwanted Program (VirusTotal only, needs
                 a VT key set up above). Shown in orange, not red.
                 Some antivirus engines flag this - typically for a
                 bundled toolbar, adware installer, or similar - but
                 it isn't confirmed malware the way MALICIOUS is.
                 Still auto-quarantined for your review; if you decide
                 it's fine, use "Mark as Safe" in the Quarantine tab.
  UNVERIFIED  - genuinely unknown either way (this is common and
                 not itself a red flag - it just means "not found,"
                 not "found and safe")

Every optional piece above narrows that UNVERIFIED bucket down and/or
adds a chance of catching something the hash-only checks structurally
cannot.
