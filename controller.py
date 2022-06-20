#!/usr/bin/env python

import json
import nacl.encoding
import nacl.signing
import nacl.hash
from nacl.exceptions import BadSignatureError

import pd_logger

logger = pd_logger.get_logger(__name__)

import keymgmt
from abstract.abstractcontroller import AbstractController
from provenancedata import ProvenanceData

sha256 = nacl.hash.sha256


class Controller(AbstractController):
    """Controller class"""

    def __init__(self, providers):
        super().__init__()
        self.keymgmt = keymgmt.KeyManager('pubkeys.db', 'privkeys.db')
        self.providers = providers

    def record(self, pd: ProvenanceData) -> None:
        for provider in self.providers:
            provider.record(pd)

    def retrieve(self):
        pass

    def validate(self, pd: ProvenanceData) -> bool:
        invoker_bool = self.verify_invoker(pd)
        if not invoker_bool:
            logger.error("InvokeSignature validation failed: %s", pd.InvokeSignature)

        executer_bool = self.verify_executer(pd)
        if not executer_bool:
            logger.error("ExecuteSignature validation failed: %s", pd.ExecuteSignature)

        pd_hash_bool = (pd.ProvenanceHash == pd.get_provenance_hash())
        if not pd_hash_bool:
            logger.error("ProvenanceHash does not match ProvenanceData. ProvenanceHash: %s get_provenance_hash: %s", pd.ProvenanceHash, pd.get_provenance_hash())

        return invoker_bool and executer_bool and pd_hash_bool

    def migrate(self, source_provider, destination_provider, purge):
        # target_provider.migrate(source_provider.migrate())
        pass

    def collect(self, pd: ProvenanceData) -> None:
        if pd.ProvenanceHash is None:
            pd.set_provenance_hash()

        if self.validate(pd):
            self.record(pd)
            logger.debug("Recorded: %s", pd)
        else:
            logger.error("ProvenanceData validation failed: %s", pd)

    def verify_invoker(self, pd: ProvenanceData) -> bool:
        """Verify invoker signature"""

        logger.debug("Verifying InvokeSignature: %s of ProvenanceHash %s", pd.InvokeSignature, pd.ProvenanceHash)

        key = self.keymgmt.get_public_key(pd.InvokeSignature.keyid)
        if key:
            msg = pd.get_invoker_string()
            sig = pd.InvokeSignature.signature
            return_code = keymgmt.verify(message=msg, signature=sig, pubkey=key)
        else:
            logger.warn("Key %s not in %s", pd.InvokeSignature.keyid, self.keymgmt.public_keys)
            return_code = False
        return return_code

    def verify_executer(self, pd: ProvenanceData) -> bool:
        """Verify executer signature"""

        logger.debug("Verifying ExecuteSignature: %s of ProvenanceHash %s", pd.ExecuteSignature, pd.ProvenanceHash)

        key = self.keymgmt.get_public_key(pd.ExecuteSignature.keyid)
        if key:
            msg = pd.get_executer_string()
            sig = pd.ExecuteSignature.signature
            return_code = keymgmt.verify(message=msg, signature=sig, pubkey=key)
        else:
            logger.warn("Key %s not in %s", pd.InvokeSignature.keyid, self.keymgmt.public_keys)
            return_code = False
        return return_code
