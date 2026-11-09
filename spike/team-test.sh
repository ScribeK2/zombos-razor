#!/usr/bin/env bash
# Zombo's Razor GPUI spike: run on an Ubuntu laptop, paste the whole output back.
# Usage: ./team-test.sh path/to/zombo-spike-x86_64.AppImage
set -u
A="${1:?usage: $0 path/to/zombo-spike-x86_64.AppImage}"; chmod +x "$A"
echo "== system"; . /etc/os-release; echo "$PRETTY_NAME | kernel $(uname -r) | session=${XDG_SESSION_TYPE:-?} desktop=${XDG_CURRENT_DESKTOP:-?}"
echo "== gpu"; (lspci 2>/dev/null | grep -iE 'vga|3d|display') || echo "lspci missing"
(vulkaninfo --summary 2>/dev/null | grep -E 'deviceName|driverName') || echo "vulkaninfo missing (ok)"
echo "== packages"; dpkg -l fuse3 libfuse2t64 libvulkan1 mesa-vulkan-drivers 2>/dev/null | awk '/^ii/{print $2, $3}'
echo "== run 1: hello (closes itself after 6 s)"
timeout 6 "$A" hello 2>&1 | grep -v 'not a conformant'; echo "exit=${PIPESTATUS[0]} (124 = ran fine, 0 or 1 = check output)"
echo "== run 2: widgets. A window opens. Click the input and type 'example.com'. Scroll the table fast. Close the window."
"$A" widgets 2>&1 | grep -v 'not a conformant'; echo "exit=${PIPESTATUS[0]}"
echo
echo "== Orca test (manual): press Super+Alt+S to start Orca, run '$A widgets' again,"
echo "   press Tab to reach the input and the table, use the arrow keys in the table."
echo "   Report: does Orca read the input? Does it read the cell text?"
echo "== Also report: smooth scrolling? Any flicker, blank window or crash?"
