import argparse
from .parser import parse_file


def parse_args():
    """Parse our command line arguments"""
    cmdline = argparse.ArgumentParser(description="CRS parser")
    cmdline.add_argument(
        "-f",
        "--files",
        metavar="FILE",
        required=True,
        nargs="*",
        help="files to read, if empty, stdin is used",
    )
    return cmdline.parse_args()

def cli(args: list[str] = None):
    for file in args.files:
        with open(file, "r") as f:
            parse_file(f.read())


def run():
    """Runs the example parser"""
    args = parse_args()
    cli(args)


if __name__ == "__main__":
    run()

