from PIL import Image, ImageDraw, ImageFont
import os

OUTPUT_FILE = "../init/tui/title.txt"
FONT_FILE = "Exo2-Bold.ttf"
TEXT = "vanguard boot"
# Render directly at target height for 1:1 pixel mapping
# A height of 16 pixels (lines) usually allows for good legibility of bold fonts
# Use 16px font size for 1:1 mapping
TARGET_HEIGHT = 16
FONT_SIZE = 16 
TEXT_COLOR = (95, 215, 255) # Color 86 roughly (Light Blue)

try:
    font = ImageFont.truetype(FONT_FILE, FONT_SIZE)
except IOError:
    # Fallback to default if load fails
    font = ImageFont.load_default()

# Measure text size
bbox = font.getbbox(TEXT)
width = bbox[2]
height = bbox[3] + 4 # Slight padding

# Create image at logical size
img = Image.new("RGB", (width, height), (0, 0, 0))
draw = ImageDraw.Draw(img)
draw.text((0, 0), TEXT, font=font, fill=TEXT_COLOR)

# No resizing! We output 1 pixel = 1 char.
target_width = width
target_height = height

print(f"Target geometry (1:1): {target_width}x{target_height}")

def rgb_to_xterm256(r, g, b):
    # Thresholding for clean block art
    # The font color was (95, 215, 255) -> roughly Cyan
    # If pixel is bright enough, make it Cyan (86)
    if r > 50 or g > 50 or b > 50:
        return 86
    return 16 # Black/Background

content = ""
# Process 2 rows at a time for half-block rendering
for y in range(0, img.height, 2):
    for x in range(img.width):
        # Get top pixel
        r1, g1, b1 = img.getpixel((x, y))
        fg_top = rgb_to_xterm256(r1, g1, b1)
        
        # Get bottom pixel (handle odd height)
        if y + 1 < img.height:
            r2, g2, b2 = img.getpixel((x, y+1))
            fg_bot = rgb_to_xterm256(r2, g2, b2)
        else:
            fg_bot = 16 # Black
            
        # Logic for half-blocks
        # We assume background is 16 (Black)
        
        # Case 1: Both Empty
        if fg_top == 16 and fg_bot == 16:
            content += "\x1b[0m "
            
        # Case 2: Both Full (Same Color) -> Full Block
        elif fg_top != 16 and fg_bot != 16:
            # Check if colors identical (simplified here, we mainly use cyan)
            content += f"\x1b[38;5;{fg_top}m█\x1b[0m"
            
        # Case 3: Top Full, Bottom Empty -> Upper Block
        elif fg_top != 16 and fg_bot == 16:
            content += f"\x1b[38;5;{fg_top}m▀\x1b[0m"
            
        # Case 4: Top Empty, Bottom Full -> Lower Block
        elif fg_top == 16 and fg_bot != 16:
            content += f"\x1b[38;5;{fg_bot}m▄\x1b[0m"
            
    content += "\n"

# Remove trailing newline
content = content.rstrip("\n")

with open(OUTPUT_FILE, "w") as f:
    f.write(content)

print(f"Generated {OUTPUT_FILE} ({target_width}x{target_height})")
