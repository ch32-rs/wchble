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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--seconds', type=float, default=40)
    args = parser.parse_args()
    deadline = time.monotonic() + args.seconds
    clicks = []
    while time.monotonic() < deadline:
        result = subprocess.run(['osascript', '-e', SCRIPT],
                                capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            clicks.append(result.stdout.strip())
            print('CLICK', result.stdout.strip(), flush=True)
        time.sleep(0.5)
    print(f'clicks={len(clicks)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
