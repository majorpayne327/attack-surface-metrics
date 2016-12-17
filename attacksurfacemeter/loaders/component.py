class Component:
    """represents a file containing functions"""

    dangerous = False
    entry = False
    exit = False

    def __init__(self,name):
        self.name = name
        self.methods = []
