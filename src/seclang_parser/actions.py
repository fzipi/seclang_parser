class Action:
    def __init__(self, action, param=None):
        self.action = action
        self.param = param

    def set_action(self, action, param):
        self.action = action
        self.param = param

    def to_string(self):
        if self.param:
            return f"{self.action}:{self.param}"
        return self.action

    def get_key(self):
        return self.action

    def __str__(self):
        return self.to_string()


class SeclangActions:
    def __init__(self):
        self.disruptive_action = None
        self.non_disruptive_actions = []
        self.flow_actions = []
        self.data_actions = []

    def to_string(self):
        results = []
        if self.disruptive_action and self.disruptive_action.action:
            results.append(self.disruptive_action.to_string())
        results.extend(action.to_string() for action in self.non_disruptive_actions)
        results.extend(action.to_string() for action in self.flow_actions)
        results.extend(action.to_string() for action in self.data_actions)
        return ", ".join(results)

    def __str__(self):
        return f"Disruptive: {self.disruptive_action}, NonDisruptive: {self.non_disruptive_actions}, Flow: {self.flow_actions}, Data: {self.data_actions}"

    def set_disruptive_action_with_param(self, action, value):
        self.disruptive_action = Action(action, value)

    def set_disruptive_action_only(self, action):
        self.disruptive_action = Action(action)

    def add_non_disruptive_action_with_param(self, action, param):
        self.non_disruptive_actions.append(Action(action, param))

    def add_non_disruptive_action_only(self, action):
        self.non_disruptive_actions.append(Action(action))

    def add_flow_action_with_param(self, action, param):
        self.flow_actions.append(Action(action, param))

    def add_flow_action_only(self, action):
        self.flow_actions.append(Action(action))

    def add_data_action_with_params(self, action, param):
        self.data_actions.append(Action(action, param))

    def get_action_keys(self):
        keys = [action.get_key() for action in self.non_disruptive_actions]
        keys.extend(action.get_key() for action in self.flow_actions)
        keys.extend(action.get_key() for action in self.data_actions)
        return keys

    def get_action_by_key(self, key):
        for action in self.non_disruptive_actions:
            if action.get_key() == key:
                return action
        for action in self.flow_actions:
            if action.get_key() == key:
                return action
        for action in self.data_actions:
            if action.get_key() == key:
                return action
        return None

    def get_actions_by_key(self, key):
        actions = [action for action in self.non_disruptive_actions if action.get_key() == key]
        actions.extend(action for action in self.flow_actions if action.get_key() == key)
        actions.extend(action for action in self.data_actions if action.get_key() == key)
        return actions