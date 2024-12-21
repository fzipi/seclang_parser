from .actions import SeclangActions
from .metadata import SecRuleMetadata
from .operators import Operator
from .variables import Variables


class SeclangDirective:
    def to_seclang(self):
        raise NotImplementedError("Subclasses should implement this method")

    def _to_seclang_base(self, directive_name, phase, transformations, seclang_actions, comment):
        result = f"{comment}{directive_name} \"phase:{phase}"
        actions = seclang_actions.to_string()
        transformations_str = ', '.join(transformations)
        if actions:
            result += f", {actions}"
        if transformations_str:
            result += f", {transformations_str}"
        result += "\"\n"
        return result

    def set_id(self, value):
        pass

    def set_phase(self, value):
        pass

    def set_msg(self, value):
        pass

    def set_maturity(self, value):
        pass

    def set_rev(self, value):
        pass

    def set_severity(self, value):
        pass

    def add_tag(self, value):
        pass

    def set_ver(self, value):
        pass

    def set_disruptive_action_with_param(self, action, value):
        pass

    def set_disruptive_action_only(self, action):
        pass

    def add_non_disruptive_action_with_param(self, action, param):
        pass

    def add_non_disruptive_action_only(self, action):
        pass

    def add_flow_action_with_param(self, action, param):
        pass

    def add_flow_action_only(self, action):
        pass

    def add_data_action_with_params(self, action, param):
        pass

    def add_transformation(self, transformation):
        pass

    def set_comment(self, value):
        pass


class ConfigurationDirective(SeclangDirective):
    def __init__(self, comment='', directive_name='', parameter=''):
        self.comment = comment
        self.directive_name = directive_name
        self.parameter = parameter

    def to_seclang(self):
        return f"{self.comment}{self.directive_name} {self.parameter}\n"


class SecDefaultAction(SeclangDirective):
    def __init__(self, comment='', phase='', transformations=None, seclang_actions=None):
        self.comment = comment
        self.phase = phase
        self.transformations = transformations or []
        self.seclang_actions = seclang_actions or SeclangActions()

    def to_seclang(self):
        return self._to_seclang_base("SecDefaultAction", self.phase, self.transformations, self.seclang_actions, self.comment)


class SecAction(SeclangDirective):
    def __init__(self, comment='', phase='', transformations=None, seclang_actions=None):
        self.comment = comment
        self.phase = phase
        self.transformations = transformations or []
        self.seclang_actions = seclang_actions or SeclangActions()

    def to_seclang(self):
        return self._to_seclang_base("SecAction", self.phase, self.transformations, self.seclang_actions, self.comment)


class SecRule(SeclangDirective):
    def __init__(self, comment='', variables=None, operator=None, seclang_actions=None, chained_rule=None, metadata=None):
        self.comment = comment
        self.variables = variables or Variables()
        self.operator = operator or Operator()
        self.seclang_actions = seclang_actions or SeclangActions()
        self.chained_rule = chained_rule
        self.metadata = metadata or SecRuleMetadata()

    def to_seclang(self):
        return self.to_seclang_with_param("")

    def to_seclang_with_param(self, initial_string):
        aux_string = ",\\\n" + initial_string + "    "
        end_string = ""
        actions = self.seclang_actions.get_action_keys()
        aux_slice = []
        chained_rule = False

        result = f"{self.comment}{initial_string}SecRule "
        result += f"{self.variables.to_string()} "
        result += f"\"{self.operator.to_string()}\""
        if self.metadata.id:
            aux_slice.append(f"id:{self.metadata.id}")
        if self.metadata.phase:
            aux_slice.append(f"phase:{self.metadata.phase}")
        if self.seclang_actions.disruptive_action:
            aux_slice.append(self.seclang_actions.disruptive_action.to_string())
        if "status" in actions:
            aux_slice.append(self.seclang_actions.get_action_by_key("status").to_string())
        if "capture" in actions:
            aux_slice.append(self.seclang_actions.get_action_by_key("capture").to_string())
        if self.metadata.msg:
            aux_slice.append(f"msg:'{self.metadata.msg}'")
        for tag in self.metadata.tags:
            aux_slice.append(f"tag:'{tag}'")
        if "chain" in actions:
            chained_rule = True
            aux_slice.append(self.seclang_actions.get_action_by_key("chain").to_string())
        for i, action in enumerate(aux_slice):
            if i == 0:
                result += f" \\\n{initial_string}    \""
            else:
                result += aux_string
            result += action
            if i == len(aux_slice) - 1:
                result += "\""
            else:
                result += end_string
        result += "\n"
        if chained_rule and self.chained_rule:
            result += self.chained_rule.to_seclang_with_param(initial_string + "    ")
        return result