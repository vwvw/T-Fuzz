#!python
from tfuzz.checksum import ChecksumDetector

def main():
    c = ChecksumDetector("convert", "png/", "malformed_inputs",  target_opts=['@@', "/home/nicolasbadoux/T-Fuzz/converted.jpg"])


if __name__ == '__main__':
    main()

