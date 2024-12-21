class CommentMetadata:
    def __init__(self, comment=None):
        self.comment = comment

    def set_comment(self, value):
        self.comment = value

    def to_seclang(self):
        return self.comment


class OnlyPhaseMetadata:
    def __init__(self, comment_metadata=None, phase=None):
        self.comment_metadata = comment_metadata or CommentMetadata()
        self.phase = phase

    def to_string(self):
        return f"phase:{self.phase}"

    def set_id(self, value):
        pass

    def set_phase(self, value):
        self.phase = value

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


class SecRuleMetadata:
    def __init__(self, id=None, msg=None, maturity=None, rev=None, severity=None, tags=None, ver=None):
        self.only_phase_metadata = OnlyPhaseMetadata()
        self.id = id
        self.msg = msg
        self.maturity = maturity
        self.rev = rev
        self.severity = severity
        self.tags = tags or []
        self.ver = ver

    def to_string(self):
        result = f"{self.only_phase_metadata.to_string()}, id:{self.id}"
        if self.msg:
            result += f", msg:'{self.msg}'"
        if self.maturity:
            result += f", maturity:'{self.maturity}'"
        if self.rev:
            result += f", rev:'{self.rev}'"
        if self.severity:
            result += f", severity:'{self.severity}'"
        if self.ver:
            result += f", ver:'{self.ver}'"
        return result

    def set_id(self, value):
        if self.id is not None:
            raise ValueError("Id already set")
        self.id = int(value)

    def set_msg(self, value):
        self.msg = value

    def set_maturity(self, value):
        self.maturity = value

    def set_rev(self, value):
        self.rev = value

    def set_severity(self, value):
        self.severity = value

    def add_tag(self, value):
        self.tags.append(value)

    def set_ver(self, value):
        self.ver = value