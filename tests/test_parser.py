from seclang_parser.SecLangParser import SecLangParser
from seclang_parser.SecLangParserListener import SecLangParserListener
from seclang_parser.parser import parse_file, parse_file_with_implementation


class SecLangListener(SecLangParserListener):
    def enterStmt(self, ctx):
        print("Entering statement:", ctx.getText())

    def enterAction(self, ctx: SecLangParser.ActionContext):
        print("Entering action:", ctx.getText())

    def enterComment(self, ctx: SecLangParser.CommentContext):
        print("Entering comment:", ctx.getText())

    def enterId(self, ctx: SecLangParser.IdContext):
        print("Entering id:", ctx.getText())


def test_parse_file(crs_files):
    for file in crs_files:
        with open(file, "r") as f:
            s = f.read()
            parse_file_with_implementation(s, SecLangListener())
            assert True
