---
name: ffmpeg-filters
description: Build correct FFmpeg filter graphs using -filter_complex, with practical recipes for scaling, overlays, crossfades, speed changes, GIF creation, and concatenation -- plus the common syntax mistakes that trip up LLMs and humans alike.
---

# FFmpeg Filters

## Filter Graph Syntax

A filtergraph is a string with these structural rules:

- **Commas** (`,`) chain filters sequentially within a single linear chain.
- **Semicolons** (`;`) separate distinct linear chains from each other.
- **Square-bracket labels** (`[0:v]`, `[0:a]`, `[tmp]`) route streams between chains.

```
# Single chain: scale then crop (comma-separated)
-vf "scale=1280:720,crop=1280:600:0:60"

# Two chains connected by a label (semicolon-separated)
-filter_complex "[0:v]scale=1280:720[scaled]; [scaled]drawtext=text='Hello':fontsize=24:fontcolor=white:x=10:y=10[out]"
```

### Input Labels

Inputs are numbered from zero in the order of `-i` arguments:

| Label | Meaning |
|-------|---------|
| `[0:v]` | First input, video stream |
| `[0:a]` | First input, audio stream |
| `[1:v]` | Second input, video stream |
| `[0:v:1]` | First input, second video stream |

If a filter chain has no input label, FFmpeg tries to auto-connect it to the first unused input. This implicit wiring is a common source of bugs -- always label explicitly in complex graphs.

### Output Labels and -map

Output labels name intermediate or final streams. Use `-map` to select which labeled stream goes to the output file:

```bash
ffmpeg -i input.mp4 -i overlay.png \
  -filter_complex "[0:v][1:v]overlay=10:10[vout]" \
  -map "[vout]" -map 0:a \
  -c:v libx264 -c:a copy output.mp4
```

Without `-map`, FFmpeg picks streams automatically, which often drops audio or picks the wrong video stream when multiple outputs exist.

## Simple vs Complex: When to Use Which

Use `-vf` / `-af` when you have a single input and single output for one stream type:

```bash
ffmpeg -i input.mp4 -vf "scale=640:480" output.mp4
```

Use `-filter_complex` when you need any of:
- Multiple inputs (overlay, concat, amerge)
- Multiple outputs (split, tee)
- Mixed audio and video filtering in one graph
- Labeled intermediate streams

**Never mix** `-vf` and `-filter_complex` for the same stream type -- FFmpeg will error.

## Common Video Filters

### scale

```bash
# Scale to 1280 wide, compute height preserving aspect ratio.
# -2 ensures height is divisible by 2 (required for most codecs).
scale=1280:-2

# Force exact dimensions (may distort):
scale=1920:1080:force_original_aspect_ratio=disable

# Scale to fit within a box, preserving aspect ratio:
scale=1920:1080:force_original_aspect_ratio=decrease
```

The `-2` trick is critical: many codecs (especially H.264) require even dimensions. Using `-1` can produce odd dimensions and fail encoding.

### crop

```bash
# Crop to 1280x720, starting at (x=100, y=50):
crop=1280:720:100:50

# Center crop to 16:9 from any input:
crop=in_w:in_w*9/16

# Remove 10% from all edges:
crop=in_w*0.8:in_h*0.8
```

### overlay

```bash
# Picture-in-picture: small video at bottom-right with 10px margin
[0:v][1:v]overlay=main_w-overlay_w-10:main_h-overlay_h-10

# Watermark with transparency (PNG with alpha):
[0:v][1:v]overlay=10:10

# Time-limited overlay (show only seconds 5-15):
[0:v][1:v]overlay=10:10:enable='between(t,5,15)'
```

### drawtext

```bash
drawtext=text='Hello World':fontsize=36:fontcolor=white:\
  x=(w-text_w)/2:y=h-text_h-20:\
  borderw=2:bordercolor=black

# Show running timestamp:
drawtext=text='%{pts\:hms}':fontsize=24:fontcolor=yellow:x=10:y=10
```

On Linux, specify `fontfile=/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf` or similar. On macOS, use `font=Helvetica` instead. Colons inside filter options must be escaped with `\:` when the text contains them.

### setpts (speed change)

```bash
# 2x speed (halve PTS):
setpts=0.5*PTS

# 0.5x speed (slow motion, double PTS):
setpts=2.0*PTS

# Reset timestamps (useful after trim):
setpts=PTS-STARTPTS
```

For audio speed, use `atempo` (range 0.5 to 100.0). For factors outside 0.5--2.0, chain multiple atempo filters:

```bash
# 4x audio speed:
atempo=2.0,atempo=2.0

# 0.25x audio speed:
atempo=0.5,atempo=0.5
```

### trim

```bash
# Extract seconds 10 to 20:
trim=start=10:end=20,setpts=PTS-STARTPTS

# Audio equivalent:
atrim=start=10:end=20,asetpts=PTS-STARTPTS
```

Always follow trim with `setpts=PTS-STARTPTS` (or `asetpts=PTS-STARTPTS` for audio) to reset timestamps. Without this, the output will have a gap of silence/black at the start.

### pad

```bash
# Pad to 1920x1080, center the video:
pad=1920:1080:(ow-iw)/2:(oh-ih)/2:color=black
```

## Common Audio Filters

```bash
# Set volume (linear multiplier or dB):
volume=0.5
volume=3dB

# Fade in/out:
afade=t=in:st=0:d=2
afade=t=out:st=58:d=2

# Merge stereo channels from two mono inputs:
[0:a][1:a]amerge=inputs=2

# Normalize loudness to broadcast standard:
loudnorm=I=-16:TP=-1.5:LRA=11

# Delay audio by 500ms:
adelay=500|500
```

## Concatenation: Filter vs Demuxer

### Concat demuxer (fast, no re-encode)

Use when all clips share the same codec, resolution, and frame rate:

```bash
# Create a file list:
printf "file '%s'\n" clip1.mp4 clip2.mp4 clip3.mp4 > list.txt

ffmpeg -f concat -safe 0 -i list.txt -c copy output.mp4
```

The demuxer performs a stream-level copy -- no quality loss, near-instant. But it fails if codecs or parameters differ.

### Concat filter (re-encodes, flexible)

Use when clips differ in resolution, codec, or frame rate:

```bash
ffmpeg -i clip1.mp4 -i clip2.mp4 \
  -filter_complex \
    "[0:v]scale=1280:720,setsar=1[v0]; \
     [1:v]scale=1280:720,setsar=1[v1]; \
     [v0][0:a][v1][1:a]concat=n=2:v=1:a=1[vout][aout]" \
  -map "[vout]" -map "[aout]" output.mp4
```

The `n=2` parameter must match the number of segments. Each segment must provide exactly `v` video and `a` audio streams (as specified). Forgetting `setsar=1` causes aspect ratio glitches when inputs have different SAR values.

## Crossfade with xfade

```bash
# 1-second crossfade between two 10-second clips.
# offset = duration_of_first_clip - crossfade_duration = 9
ffmpeg -i clip1.mp4 -i clip2.mp4 \
  -filter_complex \
    "[0:v][1:v]xfade=transition=fade:duration=1:offset=9[vout]; \
     [0:a][1:a]acrossfade=d=1[aout]" \
  -map "[vout]" -map "[aout]" output.mp4
```

The `offset` is in seconds from the start of the output timeline -- not from the second clip. Getting offset wrong is the most common xfade mistake.

Available transitions include: fade, wipeleft, wiperight, wipeup, wipedown, slideleft, slideright, circlecrop, fadeblack, fadewhite, radial, and more.

## High-Quality GIF Creation

The two-pass palette approach produces dramatically better GIFs:

```bash
# Pass 1: generate optimal 256-color palette
ffmpeg -i input.mp4 -vf "fps=15,scale=480:-2:flags=lanczos,palettegen" palette.png

# Pass 2: encode using the palette
ffmpeg -i input.mp4 -i palette.png \
  -filter_complex "[0:v]fps=15,scale=480:-2:flags=lanczos[v]; \
                    [v][1:v]paletteuse=dither=bayer:bayer_scale=3" \
  output.gif
```

Without palettegen/paletteuse, FFmpeg uses a generic palette and the output looks washed out with heavy banding.

## Thumbnail Grid

```bash
# Extract one frame per minute and tile into a 4-column grid:
ffmpeg -i input.mp4 \
  -vf "select='not(mod(n\,1800))',scale=320:-2,tile=4x0" \
  -frames:v 1 -vsync vfr thumbnails.png
```

The `tile=4x0` means 4 columns, unlimited rows. Use `select` with frame number expressions -- `not(mod(n\,1800))` picks every 1800th frame (one per minute at 30fps).

## Hardware Acceleration

```bash
# macOS (VideoToolbox) -- no CRF, use -b:v or -q:v:
ffmpeg -i input.mp4 -c:v h264_videotoolbox -b:v 6000k output.mp4

# Linux (NVENC) -- use -cq for constant quality, -preset p1 to p7:
ffmpeg -hwaccel cuda -i input.mp4 -c:v h264_nvenc -preset p4 -cq 23 output.mp4
```

Hardware encoders cannot use `-crf`. They have their own quality parameters (`-q:v` for VideoToolbox, `-cq` for NVENC). Passing `-crf` to a hardware encoder is silently ignored or causes an error. Filters still run on CPU even when using hardware encode/decode.

## Common Mistakes

1. **Semicolons vs commas confusion.** Semicolons separate independent chains; commas chain filters within one chain. Using the wrong one produces "No such filter" or silent graph misconstruction.

2. **Missing `-map` with `-filter_complex`.** Without explicit mapping, FFmpeg may ignore your filter output and pick a raw input stream instead.

3. **Odd dimensions from `scale=W:-1`.** Use `scale=W:-2` to guarantee even dimensions. H.264 and H.265 require this.

4. **Forgetting `setpts=PTS-STARTPTS` after `trim`.** The output timestamps will be wrong, causing players to show black/silence before the content begins.

5. **Quoting issues in shells.** Double-quote the entire filtergraph. Use `\:` to escape colons inside filter parameters like drawtext. In some shells, semicolons need escaping or the whole expression must be quoted.

6. **Filter order matters.** `scale` before `crop` gives different results than `crop` before `scale`. Think about what each filter expects as input.

7. **Mixing `-vf` and `-filter_complex`.** FFmpeg does not allow both for the same stream type in one command. Pick one.

8. **`atempo` range is 0.5 to 100.0.** For slower than 0.5x or specific large speedups, chain multiple atempo filters.

9. **Pixel format mismatches.** Some filters output formats that downstream filters or encoders cannot accept. Insert `format=yuv420p` before encoding if you get "Discarding unsupported subtypes" or similar errors.

10. **Concat filter segment count.** The `n=` parameter must exactly match the number of input segments. Off-by-one here produces cryptic errors or silent truncation.

