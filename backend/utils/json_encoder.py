from decimal import Decimal


def json_encoder(obj):
    if isinstance(obj, Decimal):
        return str(obj)
    raise TypeError("Object of type '%s' is not JSON serializable" % type(obj).__name__)


def json_decimal_encoder(obj):
    if isinstance(obj, Decimal):
        return int(obj)
    if isinstance(obj, bytes):
        return str(obj)
    raise TypeError("Object of type '%s' is not JSON serializable" % type(obj).__name__)