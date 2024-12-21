class Variables:
    def __init__(self):
        self.variables = []

    def to_string(self):
        return "|".join(self.variables)

    def add_variable(self, variable):
        self.variables.append(variable)