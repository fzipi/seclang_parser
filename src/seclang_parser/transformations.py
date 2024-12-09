class Transformations:
    def __init__(self):
        self.transformations = []

    def add_transformation(self, transformation):
        self.transformations.append(transformation)

    def to_string(self):
        results = [f"t:{transformation}" for transformation in self.transformations]
        return ",".join(results)