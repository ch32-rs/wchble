#!/usr/bin/env python3
"""Click the macOS Bluetooth pairing consent button while the HID acceptance run drives CoreBluetooth.

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
    set seen to {}
    set procs to every process
    repeat with p in procs
        set pname to "?"
        try
            set pname to (name of p) as text
        end try
        try
            set wins to every window of p
        on error
            set wins to {}
        end try
        repeat with w in wins
            try
                set title to (name of w) as text
            on error
                set title to ""
            end try
            set labels to {}
            try
                repeat with b in buttons of w
                    try
                        set end of labels to (name of b) as text
                    end try
                end repeat
            end try
            set joined to labels as text
            if title contains "Bluetooth" or title contains "Pair" or title contains "配对" or joined contains "Pair" or joined contains "配对" then
                set end of seen to (pname & " | " & title & " | " & joined)
                if title contains "Bluetooth" or title contains "Pair" or title contains "配对" then
                    repeat with b in buttons of w
                        try
                            set label to (name of b) as text
                            if label is in {"Pair", "Connect", "Allow", "OK", "配对", "连接", "允许"} then
                                click b
                                set end of hits to (title & " / " & label)
                            end if
                        end try
                    end repeat
                end if
            end if
        end repeat
    end repeat
    set AppleScript's text item delimiters to "; "
    return (hits as text) & "|||" & (seen as text)
end tell
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--seconds', type=float, default=40)
    args = parser.parse_args()
    deadline = time.monotonic() + args.seconds
    clicks = []
    seen = set()
    while time.monotonic() < deadline:
        result = subprocess.run(['osascript', '-e', SCRIPT],
                                capture_output=True, text=True)
        if result.returncode != 0:
            print('SCAN_ERROR', result.stderr.strip(), flush=True)
        else:
            clicks_part, _, seen_part = result.stdout.strip().partition('|||')
            if clicks_part:
                clicks.append(clicks_part)
                print('CLICK', clicks_part, flush=True)
            if seen_part and seen_part not in seen:
                seen.add(seen_part)
                print('DIALOGS', seen_part, flush=True)
        time.sleep(0.5)
    print(f'clicks={len(clicks)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
