from pyasn1.codec.der import decoder
from pyasn1.type import univ, namedtype

from asn1_class_models.algorithm_identifier import AlgorithmIdentifier

class DigestInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('digestAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('digest', univ.OctetString())
    )