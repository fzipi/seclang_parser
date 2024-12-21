from seclang_parser.parser import parse_file


def test_parse_file(crs_files):
    for file in crs_files:
        print("Parsing file:", file)
        with open(file, "r") as f:
            s = f.read()

            parse_file(s)
