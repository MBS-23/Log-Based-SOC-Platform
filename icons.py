from PIL import Image

img = Image.open("assets/icons/logsoc.png")
img.save(
    "assets/icons/logsoc.ico",
    format="ICO",
    sizes=[(16,16),(32,32),(48,48),(64,64),(128,128),(256,256)]
)
