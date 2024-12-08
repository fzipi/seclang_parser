from antlr4 import *

from .SecLangLexer import SecLangLexer
from .SecLangParserListener import SecLangParserListener
from .SecLangParser import SecLangParser
from .errors import LexerErrorListener, ParserErrorListener


def parse_file_with_implementation(s: str, impl: SecLangParserListener) -> list:
    p = _prepare_parser(s)
    tree = p.configuration()
    walker = ParseTreeWalker()
    walker.walk(impl, tree)

def parse_file(s: str) -> list:
    parser = _prepare_parser(s)

    # invoke the parser on rule "r"
    tree = parser.configuration()
    walker = ParseTreeWalker()
    listener = DefaultParserImpl()
    walker.walk(listener, tree)

def _prepare_parser(s):
    stream = InputStream(s)
    lexer = SecLangLexer(stream)
    token_stream = CommonTokenStream(lexer)
    parser = SecLangParser(token_stream)
    # register our own error listeners
    lexer.removeErrorListeners()
    lexer.addErrorListener(LexerErrorListener())
    parser.removeErrorListeners()
    parser.addErrorListener(ParserErrorListener())
    return parser


class DefaultParserImpl(SecLangParserListener):
    def __init__(self):
        self.comments = []
        self.ids = []

    def enterComment(self, ctx: SecLangParser.CommentContext):
        self.comments.append(ctx.getText())

    def enterId(self, ctx:SecLangParser.IdContext):
        self.ids.append(ctx.getText())


