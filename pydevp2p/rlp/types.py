from rlp.sedes import List, Serializable
from rlp.exceptions import SerializationError, DeserializationError, ListDeserializationError, ListSerializationError
from rlp.codec import is_sequence
from pydevp2p.rlp.extention import RLPMessage
from pydevp2p.utils import bytes_to_hex, bytes_to_int, hex_to_bytes, int_to_bytes
from rlp.sedes import CountableList


class IPAddress(object):
    """A sedes for IP addresses.
    :param l: the size of the serialized representation in bytes or `None` to
              use the shortest possible one
    """

    def __init__(self, l=None):
        # TODO use this to differentiate IPv4 and IPv6
        self.l = l

    def serialize(self, obj):
        if not isinstance(obj, str):
            raise SerializationError('Can only serialize strings', obj)
        # if self.l is not None and obj >= 256**self.l:
        #     raise SerializationError('Integer too large (does not fit in {} '
        #                              'bytes)'.format(self.l), obj)
        if len(obj) < 8 or len(obj) > 15:
            raise SerializationError('Invalid IPV4 Address', obj)

        try:
            ip_as_bytes = bytes(map(int, obj.split(".")))
            return ip_as_bytes
        except Exception as e:
            raise SerializationError(e, obj=obj)

    def deserialize(self, serial):
        if self.l is not None and len(serial) != self.l:
            raise DeserializationError('Invalid serialization (wrong size)',
                                       serial)
        if self.l is None and len(serial) > 0 and serial[0:1] == b'\x00':
            raise DeserializationError('Invalid serialization (not minimal '
                                       'length)', serial)

        return ".".join(f'{c}' for c in serial)


ip_address = IPAddress()


class HexValue(object):
    """A sedes for a hex value."""

    def __init__(self):
        pass

    def serialize(self, obj):
        try:
            return hex_to_bytes(obj)
        except Exception as e:
            raise SerializationError(e, obj=obj)

    def deserialize(self, serial):
        try:
            return bytes_to_hex(serial)
        except Exception as e:
            raise DeserializationError(e, serial=serial)


hex_value = HexValue()


class Hex32OrIntValue(object):
    """A sedes for a hex value."""

    def __init__(self):
        pass

    def serialize(self, obj):
        try:
            return hex_to_bytes(obj)
        except Exception as e:
            raise SerializationError(e, obj=obj)

    def deserialize(self, serial):
        try:
            return bytes_to_int(serial) if len(serial) < 30 else bytes_to_hex(serial)
        except Exception as e:
            raise DeserializationError(e, serial=serial)


hex_or_int_value = Hex32OrIntValue()


class DateValue(object):
    """A sedes for a date value."""

    def __init__(self):
        pass

    def serialize(self, obj):
        # Int timestamp to bytes
        try:
            return int_to_bytes(obj)
        except Exception as e:
            raise SerializationError(e, obj=obj)

    def deserialize(self, serial):
        # bytes -> parsed string date
        from time import strftime, localtime
        try:
            return strftime('%Y-%m-%d %H:%M:%S', localtime(bytes_to_int(serial)))
        except Exception as e:
            raise DeserializationError(e, serial=serial)


date_value = DateValue()


class VariableList(object):

    """A sedes for lists of arbitrary length.
    :param element_sedes: when (de-)serializing a list, this sedes will be
                          applied to all of its elements
    :param max_length: maximum number of allowed elements, or `None` for no limit
    """

    def __init__(self, element_sedes: Serializable, max_length=None):
        self.element_sedes = element_sedes
        self.max_length = max_length

    def __iter__(self):
        for element in self.element_sedes:
            print(element)
            yield element

    def serialize(self, obj):
        return self.element_sedes.serialize(obj)

    def deserialize(self, serial):
        if len(serial) != len(self.element_sedes._meta.fields):
            print(f"ERROR: {serial}")
            raise ListDeserializationError(
                'Wrong Number of Items in List', serial=serial)
        return self.element_sedes.deserialize(serial)
