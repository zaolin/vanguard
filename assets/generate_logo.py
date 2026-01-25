from PIL import Image
import os

OUTPUT_FILE = "../init/tui/logo.txt"
INPUT_FILE = "tui_icon.png"

# Target Size: Large
# 40 chars wide
# 20 lines high
WIDTH = 40
HEIGHT = 40

img = Image.open(INPUT_FILE)

# 1. Crop to content (trim transparent/black borders)
# Use a threshold to handle near-black compression artifacts
def get_bbox_threshold(image, threshold=15):
    img = image.convert("RGB")
    width, height = img.size
    left, top, right, bottom = width, height, 0, 0
    
    found = False
    pixels = img.load()
    
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            if max(r, g, b) > threshold:
                found = True
                left = min(left, x)
                top = min(top, y)
                right = max(right, x)
                bottom = max(bottom, y)
                
    if not found:
        return None
    return (left, top, right + 1, bottom + 1)

bbox = get_bbox_threshold(img)
if bbox:
    print(f"Original size: {img.size}")
    print(f"Cropping to bbox: {bbox}")
    img = img.crop(bbox)
else:
    print("Warning: No content found in image!")

# 2. Resize to specific width, maintaining aspect
# We don't force a square canvas anymore. We let lipgloss center the result.
# Target width roughly 40-50 chars
TARGET_WIDTH = 46
aspect = img.width / img.height
new_w = TARGET_WIDTH
new_h = int(TARGET_WIDTH / aspect)

img = img.resize((new_w, new_h), Image.Resampling.NEAREST)

# 3. No padding/centering on canvas. Just output the tight crop.
# This is CRITICAL for lipgloss.Center to work correctly.
# If we add padding here, lipgloss centers the padding + logo, 
# which looks off-center if the logo isn't perfectly centered in the padding.
bbox = get_bbox_threshold(img)
if bbox:
    img = img.crop(bbox)
    WIDTH, HEIGHT = img.size
    print(f"Final logo size: {WIDTH}x{HEIGHT}")
else:
    WIDTH, HEIGHT = img.size

img = img.convert("RGB")


def rgb_to_xterm256(r, g, b):
    # Basic 6x6x6 color cube mapping
    parts = [0x00, 0x5f, 0x87, 0xaf, 0xd7, 0xff]
    def get_closest_part(val):
        return min(range(len(parts)), key=lambda i: abs(parts[i] - val))

    ir = get_closest_part(r)
    ig = get_closest_part(g)
    ib = get_closest_part(b)
    return 16 + (ir * 36) + (ig * 6) + ib

content = ""

for y in range(0, HEIGHT, 2):
    for x in range(WIDTH):
        r1, g1, b1 = img.getpixel((x, y))
        r2, g2, b2 = img.getpixel((x, y+1))
        
        fg = rgb_to_xterm256(r1, g1, b1)
        bg = rgb_to_xterm256(r2, g2, b2)
        
        content += f"\x1b[38;5;{fg}m\x1b[48;5;{bg}m▀\x1b[0m"
    
    content += "\n"

content = content.rstrip("\n")

with open(OUTPUT_FILE, "w") as f:
    f.write(content)

print(f"Generated {OUTPUT_FILE} ({WIDTH}x{HEIGHT})")
