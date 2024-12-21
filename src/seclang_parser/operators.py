class Operator:
    def __init__(self, name='', value=''):
        self.name = name
        self.value = value

    def set_operator_name(self, name):
        self.name = name

    def set_operator_value(self, value):
        self.value = value

    def to_string(self):
        return f"@{self.name} {self.value}"