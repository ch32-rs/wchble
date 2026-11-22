#!/usr/bin/env python3
"""Click the macOS Bluetooth pairing consent button while a peripheral test runs.

macOS asks for confirmation before it will pair with a peripheral that sent a
Security Request; an unattended differential stalls until the dialog is
answered. This helper only presses the affirmative button of a Bluetooth
pairing dialog and never touches any other window.
"""
import argparse
import subprocess
import sys
import time

SCRIPT = r'''
tell application "System Events"
    set hits to {}
    repeat with p in (every process whose background only is false)
        try
            repeat with w in windows of p
                set title to (name of w) as text
                if title contains "Bluetooth" or title contains "Pair" then
                    repeat with b in buttons of w
                        set label to (name of b) as text
                        if label is in {"Pair", "Connect", "Allow", "OK", "配对", "连接", "允许"} then
                            click b
                            set end of hits to (title & " / " & label)
                        end if
                    end repeat
                end if
            end repeat
        end try
    end repeat
    set AppleScript's text item delimiters to "; "
    return hits as text
end tell
'''

# Diagnostic only: every visible window title, to see what the pairing
# prompt actually looks like when the affirmative-button search misses.
LIST_SCRIPT = r'''
tell application "System Events"
    set titles to {}
    repeat with p in (every process whose background only is false)
        try
            repeat with w in windows of p
                set end of titles to ((name of p) as text) & ": " & ((name of w) as text)
            end repeat
        end try
    end repeat
    set AppleScript's text item delimiters to "; "
    return titles as text
end tell
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--seconds', type=float, default=40)
    args = parser.parse_args()
    deadline = time.monotonic() + args.seconds
    clicks = []
    polls = 0
    while time.monotonic() < deadline:
        polls += 1
        result = subprocess.run(['osascript', '-e', SCRIPT],
                                 capture_output=True, text=True)
        if result.returncode != 0:
            print(f'OSA-ERROR {result.stderr.strip()[:160]}', flush=True)
        elif result.stdout.strip():
            clicks.append(result.stdout.strip())
            print('CLICK', result.stdout.strip(), flush=True)
        if polls % 4 == 0:
            listing = subprocess.run(['osascript', '-e', LIST_SCRIPT],
                                      capture_output=True, text=True)
            print('WINDOWS', listing.stdout.strip()[:400], flush=True)
        time.sleep(0.5)
    print(f'clicks={len(clicks)} polls={polls}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
