class ProtocolError(Exception): pass
class AuthenticationError(Exception): pass
class ValueMismatchError(Exception): pass
class NoArgumentsError(Exception): pass
class UserCancelled(Exception): pass
class UserSetupNeeded(Exception): pass
class NoOpenIDArgs(Exception): pass