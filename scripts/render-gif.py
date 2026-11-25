#!/usr/bin/env python3
"""Render demo/transcript.txt as a terminal-typing GIF.

The transcript is generated from real CLI runs (scripts/capture-demo.sh);
this script only renders it, never edits the content.

Frames are written as PNGs to a temp dir and encoded with ffmpeg
(streaming, low memory) instead of holding every frame in RAM.
"""
from PIL import Image, ImageDraw, ImageFont
import os
import shutil
import subprocess
import sys
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FRAMES_DIR = "/tmp/kevgap-gif-frames"

W = 1240
BG = (18, 18, 24)
FG = (220, 220, 220)
DIM = (150, 150, 160)
GREEN = (120, 220, 130)
YELLOW = (235, 200, 100)
RED = (240, 110, 110)
CYAN = (120, 200, 230)

font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 12)
bold = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 12)
LINE_H = 16

lines = open(os.path.join(ROOT, "demo", "transcript.txt")).read().splitlines()
# Wrap over-long lines at word boundaries for display only: the
# transcript itself is unchanged, but a long line would otherwise
# run off the right edge of the 1240px canvas.
# Wrap width 112 chars at font 12. The audit table is 106 columns
# wide, so it must not wrap (a wrapped STATUS column reads as
# broken output in the GIF).
display_lines: list[str] = []
for _raw in lines:
    if len(_raw) <= 112:
        display_lines.append(_raw)
    else:
        display_lines.extend(
            textwrap.wrap(_raw, width=112, subsequent_indent="  ", break_on_hyphens=False)
        )
lines = display_lines
# Fixed-height scrolling terminal viewport: the transcript is long,
# so a full-height canvas OOMs the encoder. Show the last VIEW_LINES
# lines like a real terminal scrolling; content is unchanged.
VIEW_LINES = 38
H = 14 + VIEW_LINES * LINE_H + 44


def color_for(line: str):
    if line.startswith("$"):
        return GREEN
    if line.startswith("#"):
        return DIM
    if "EXPOSED" in line or "REGRESSION" in line or "regression(s)" in line:
        return RED
    if "SAFE" in line or "no regressions" in line or "closed" in line:
        return GREEN
    if "AT-RISK" in line or "UNKNOWN" in line:
        return YELLOW
    if line.startswith("summary:") or line.startswith("diff:"):
        return CYAN
    if line.startswith("exit:"):
        return RED
    return FG


def render(canvas_tmp):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    y = 14
    for text, color in canvas_tmp[-VIEW_LINES:]:
        f = bold if text.startswith("$") else font
        d.text((14, y), text, font=f, fill=color)
        y += LINE_H
        if y > H - 30:
            break
    d.rectangle([14, H - 24, 22, H - 12], fill=GREEN)
    return img


shutil.rmtree(FRAMES_DIR, ignore_errors=True)
os.makedirs(FRAMES_DIR)

n = 0


def save(img):
    global n
    n += 1
    img.save(os.path.join(FRAMES_DIR, f"frame{n:04d}.png"))


# Title card (3s at 20 fps).
title = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(title)
d.text((14, 120), "kevgap - the gap between listed and fixed, in days", font=bold, fill=GREEN)
d.text((14, 170), "1. init: scaffold an inventory + config", font=font, fill=FG)
d.text((14, 200), "2. audit: GT13 inventory vs the REAL KEV snapshot - 3 EXPOSED", font=font, fill=FG)
d.text((14, 230), "3. check: a CI gate - exit 1 while anything is past its due date", font=font, fill=FG)
d.text((14, 260), "4. diff: the exposure window is still growing", font=font, fill=FG)
d.text((14, 290), "5. explain: CVE-2026-16232 - listed 22 Jul, due 25 Jul, 123 days overdue", font=font, fill=FG)
d.text((14, 320), "zero-dep CLI - 100% local, no network in audit/check/diff/explain", font=font, fill=DIM)
d.text((14, 350), "operator-declared status only: never infers SAFE from version numbers", font=font, fill=DIM)
for _ in range(60):
    save(title.copy())


# Caption card for the audit -> check transition (0.4s at 20 fps).
CAPTION_FRAMES = 8


def caption_card():
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.text((14, 120), "2. audit - the real KEV snapshot, joined to your inventory", font=bold, fill=GREEN)
    d.text((14, 170), "Check Point SmartConsole: EXPOSED, 123 days past its KEV due date", font=font, fill=FG)
    d.text((14, 200), "Citrix NetScaler and Ivanti Connect Secure: EXPOSED too", font=font, fill=FG)
    d.text((14, 230), "OpenSSH: patched, but 1 day past due - the gap is reported, not hidden", font=font, fill=FG)
    return img


# Extra hold frames so a first-time viewer can actually read the
# summary and the gate result. Total target is ~25-30 s at 20 fps.
def extra_holds(line: str) -> int:
    if line.startswith("summary:"):
        return 12
    if line.startswith("GATE"):
        return 12
    if line.startswith("diff:"):
        return 8
    if line.startswith("- [window-growing]"):
        return 6
    if line.startswith("exit:"):
        return 6
    if line.startswith("KEV listed:") or line.startswith("days past"):
        return 8
    if line.startswith("  reason:"):
        return 3
    return 0


canvas: list[tuple[str, tuple]] = []
command_count = 0
current_command = ""
for line in lines:
    color = color_for(line)
    # Caption card at the audit -> check transition, before the screen
    # clears for the check command.
    if line.startswith("$ kevgap check"):
        cap = caption_card()
        for _ in range(CAPTION_FRAMES):
            save(cap.copy())
    # Clear the screen at each new command (like a real `clear` between
    # demo steps). Without this the 38-line viewport scrolls on nearly
    # every frame and the GIF balloons.
    if line.startswith("$") and command_count >= 1:
        canvas = []
    if line.startswith("$"):
        command_count += 1
        parts = line.split()
        current_command = parts[1] if len(parts) > 1 else ""
    # Four frames per line at 20 fps (0.2 s/line): a readable typing
    # pace that lands the ~67-line transcript near 30 s with the
    # holds below. The check segment renders at 3 frames/line
    # because its compact output is quick to read.
    save(render(canvas + [(line, color)]))
    save(render(canvas + [(line, color)]))
    save(render(canvas + [(line, color)]))
    if current_command != "check":
        save(render(canvas + [(line, color)]))
    canvas.append((line, color))
    for _ in range(extra_holds(line)):
        save(render(canvas))

out = os.path.join(ROOT, "demo", "kevgap-demo.gif")
# Hold the final frame so the closing explain lines stay readable.
for _ in range(60):
    save(render(canvas))
cmd = [
    "ffmpeg", "-y", "-v", "error",
    "-framerate", "20", "-i", os.path.join(FRAMES_DIR, "frame%04d.png"),
    "-vf", "split[s0][s1];[s0]palettegen=max_colors=256[p];[s1][p]paletteuse",
    out,
]
res = subprocess.run(cmd)
if res.returncode != 0:
    print("ffmpeg failed", file=sys.stderr)
    sys.exit(1)
shutil.rmtree(FRAMES_DIR, ignore_errors=True)
size = os.path.getsize(out)
print(f"GIF written: {out} ({n} frames, {n * 50 / 1000:.1f}s, {size} bytes)")
