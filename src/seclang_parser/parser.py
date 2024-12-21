from antlr4 import *

from .SecLangLexer import SecLangLexer
from .SecLangParserListener import SecLangParserListener
from .SecLangParser import SecLangParser
from .errors import LexerErrorListener, ParserErrorListener
from .configuration import Configuration, ConfigurationList
from .metadata import CommentMetadata
from .directives import SecDefaultAction, SecAction, SecRule, ConfigurationDirective
from .operators import Operator


def parse_file_with_implementation(s: str, impl: SecLangParserListener):
    p = _prepare_parser(s)
    tree = p.configuration()
    walker = ParseTreeWalker()
    walker.walk(impl, tree)


def parse_file(s: str):
    parser = _prepare_parser(s)

    tree = parser.configuration()
    walker = ParseTreeWalker()
    listener = DefaultParserImpl()
    print(tree)
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
        super().__init__()
        self.comment = ""
        self.directive = None
        self.configuration_directive = None
        self.chained_next_rule = None
        self.configuration = None
        self.configuration_list = ConfigurationList()

    def enterConfiguration(self, ctx: SecLangParser.ConfigurationContext):
        self.configuration = Configuration()
        self.chained_next_rule = None

    def exitConfiguration(self, ctx: SecLangParser.ConfigurationContext):
        self.configuration_list.configurations.append(self.configuration)

    def enterConfig_dir_sec_default_action(self, ctx: SecLangParser.Config_dir_sec_default_actionContext):
        self.directive = SecDefaultAction()
        self.configuration.directives.append(self.directive)
        self.directive.set_comment(ctx.getText())

    def enterConfig_dir_sec_action(self, ctx: SecLangParser.Config_dir_sec_actionContext):
        self.directive = SecAction()
        self.configuration.directives.append(self.directive)
        self.directive.set_comment(ctx.getText())

    def enterEngine_config_directive_with_param(self, ctx: SecLangParser.Engine_config_directive_with_paramContext):
        self.configuration_directive = ConfigurationDirective(directive_name=ctx.getText())
        self.configuration.directives.append(self.configuration_directive)

    def enterValues(self, ctx: SecLangParser.ValuesContext):
        print("Values:", ctx.getText())
        self.configuration_directive.parameter = ctx.getText()

    def enterEngine_config_sec_cache_transformations(self, ctx: SecLangParser.Engine_config_sec_cache_transformationsContext):
        self.configuration_directive = ConfigurationDirective(directive_name=ctx.getText())
        self.configuration.directives.append(self.configuration_directive)

    def enterOption_list(self, ctx: SecLangParser.Option_listContext):
        self.configuration_directive.parameter += " " + ctx.getText()

    def enterRules_directive(self, ctx: SecLangParser.Rules_directiveContext):
        if self.chained_next_rule:
            self.directive = self.chained_next_rule
            self.chained_next_rule = None
        else:
            self.directive = SecRule()
            self.configuration.directives.append(self.directive)

    def exitStmt(self, ctx: SecLangParser.StmtContext):
        if self.comment:
            self.configuration.directives.append(CommentMetadata(comment=self.comment))
            self.comment = ""

    def enterACTION_ID(self, ctx: SecLangParser.ACTION_IDContext):
        self.directive.set_id(ctx.getText())

    def enterACTION_PHASE(self, ctx: SecLangParser.ACTION_PHASEContext):
        self.directive.set_phase(ctx.getText())

    def enterACTION_MSG(self, ctx: SecLangParser.ACTION_MSGContext):
        self.directive.set_msg(ctx.getText())

    def enterACTION_MATURITY(self, ctx: SecLangParser.ACTION_MATURITYContext):
        self.directive.set_maturity(ctx.getText())

    def enterACTION_REV(self, ctx: SecLangParser.ACTION_REVContext):
        self.directive.set_rev(ctx.getText())

    def enterACTION_SEVERITY(self, ctx: SecLangParser.ACTION_SEVERITYContext):
        self.directive.set_severity(ctx.getText())

    def enterACTION_TAG(self, ctx: SecLangParser.ACTION_TAGContext):
        self.directive.add_tag(ctx.getText())

    def enterACTION_VER(self, ctx: SecLangParser.ACTION_VERContext):
        self.directive.set_ver(ctx.getText())

    def enterDisruptive_action_only(self, ctx: SecLangParser.Disruptive_action_onlyContext):
        self.directive.set_disruptive_action_only(ctx.getText())

    def enterNon_disruptive_action_only(self, ctx: SecLangParser.Non_disruptive_action_onlyContext):
        self.directive.add_non_disruptive_action_only(ctx.getText())

    def enterFlow_action_only(self, ctx: SecLangParser.Flow_action_onlyContext):
        self.directive.add_flow_action_only(ctx.getText())
        self.directive.chained_rule = SecRule()
        self.chained_next_rule = self.directive.chained_rule

    def enterDisruptive_action_with_params(self, ctx: SecLangParser.Disruptive_action_with_paramsContext):
        self.directive.set_disruptive_action_with_param(ctx.getText(), ctx.getText())

    def enterNon_disruptive_action_with_params(self, ctx: SecLangParser.Non_disruptive_action_with_paramsContext):
        self.directive.add_non_disruptive_action_with_param(ctx.getText(), ctx.getText())

    def enterFlow_action_with_params(self, ctx: SecLangParser.Flow_action_with_paramsContext):
        self.directive.add_flow_action_with_param(ctx.getText(), ctx.getText())

    def enterData_action_with_params(self, ctx: SecLangParser.Data_action_with_paramsContext):
        self.directive.add_data_action_with_params(ctx.getText(), ctx.getText())

    def enterTransformation_action_value(self, ctx: SecLangParser.Transformation_action_valueContext):
        self.directive.add_transformation(ctx.getText())

    def enterAction_value_types(self, ctx: SecLangParser.Action_value_typesContext):
        #self.directive.seclang_actions.set_action_value(ctx.getText())
        pass

    def enterString_literal(self, ctx: SecLangParser.String_literalContext):
        # self.directive.set_param(ctx.getText())
        print("String literal:", ctx.getText())

    def enterVar_stmt(self, ctx: SecLangParser.Var_stmtContext):
        self.directive.variables.add_variable(ctx.getText())

    def enterOperator_name(self, ctx: SecLangParser.Operator_nameContext):
        self.directive.operator.set_operator_name(ctx.getText())

    def enterOperator_value(self, ctx: SecLangParser.Operator_valueContext):
        self.directive.operator.set_operator_value(ctx.getText())

    def enterString_engine_config_directive(self, ctx: SecLangParser.String_engine_config_directiveContext):
        self.configuration_directive = ConfigurationDirective(directive_name=ctx.getText())
        self.configuration.directives.append(self.configuration_directive)

    def enterSec_marker_directive(self, ctx: SecLangParser.Sec_marker_directiveContext):
        self.configuration_directive = ConfigurationDirective(directive_name=ctx.getText())
        self.configuration_list.configurations.append(self.configuration)
        self.configuration = Configuration(marker=self.configuration_directive)

    def enterComment(self, ctx: SecLangParser.CommentContext):
        self.comment = ctx.getText()