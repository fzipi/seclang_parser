from antlr4.error.ErrorListener import ErrorListener
from antlr4.error.Errors import ParseCancellationException

class RaisingErrorListener(ErrorListener):
    def syntaxError(self, recognizer, offending_symbol, line, column, msg, e):
        error_str = "line " + str(line) + ":" + str(column) + " " + msg + "\n"
        error_str += self._underline_error(recognizer, offending_symbol, line, column)
        raise ParseCancellationException(error_str)

    def _underline_error(self, recognizer, offending_symbol, line, column):
        pass


# The algorithm of underline_error was adopted from Terence Parr's book "The Definitive ANTLR 4 Reference", page 156.
class LexerErrorListener(RaisingErrorListener):
    def _underline_error(self, recognizer, offending_symbol, line, column):
        lexer_input = str(recognizer.inputStream)
        error_line = lexer_input.split("\n")[line - 1]

        output = error_line + "\n"
        for _ in range(0, column):
            output += " "
        output += "^"
        return output


class ParserErrorListener(RaisingErrorListener):
    def _underline_error(self, recognizer, offending_symbol, line, column):
        tokens = recognizer.getInputStream()
        parser_input = str(tokens.tokenSource.inputStream)
        error_line = parser_input.split("\n")[line - 1]

        output = error_line + "\n"
        for _ in range(0, column):
            output += " "

        start = offending_symbol.start
        stop = offending_symbol.stop
        if 0 <= start <= stop:
            for _ in range(start, stop + 1):
                output += "^"
        return output