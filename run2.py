#!python
from tfuzz.detector import Detection


def main():
    #Detection("../test", ["@@"], "/home/nicolasbadoux/test_dir","/home/nicolasbadoux/c.txt")
    #Detection("/bin/gzip", ["-d", "@@"], "/home/nicolasbadoux/test_dir", "/home/nicolasbadoux/Desktop/a.gz")
    #Detection("/usr/local/bin/magick", ["@@", "output.jpg"], "/home/nicolasbadoux/test_dir", "/home/nicolasbadoux/T-Fuzz/png/all_gray.png")
    Detection("/usr/bin/ffmpeg", ["-i", "@@", "out.mov"], "/home/nicolasbadoux/test_dir", "/home/nicolasbadoux/T-Fuzz/out.mp4")


if __name__ == '__main__':
    main()
