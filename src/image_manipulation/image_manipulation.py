import sys
from PIL import Image

im = Image.open("cylab.png")

im2 = im.transpose(2)

im2.save("cylab_transpose.png")