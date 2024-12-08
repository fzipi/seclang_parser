import sys

from antlr4 import *

from parser.SecLangLexer import SecLangLexer
from parser.SecLangParser import SecLangParser
from parser.SecLangParserListener import SecLangParserListener

class SecLangListener(SecLangParserListener):
    def enterStmt(self, ctx):
        print("Entering statement:", ctx.getText())

    def enterAction(self, ctx: SecLangParser.ActionContext):
        print("Entering action:", ctx.getText())

    def enterComment(self, ctx: SecLangParser.CommentContext):
        print("Entering comment:", ctx.getText())
