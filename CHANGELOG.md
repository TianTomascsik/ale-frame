# Changelog

## 0.2.0

- **Breaking:** `AleHeader::build` is now fallible — it returns
  `Result<Self, AleError>` and rejects payloads larger than
  `ALE_MAX_USER_DATA` with `AleError::PayloadTooLarge`, instead of silently
  truncating the 16-bit Packet Length field.
- Hardened `AleFrameReader` against malformed `packet_length` values
  (`AleError::InvalidPacketLength`).

## 0.1.0

- Initial release: ALEPKT framing per UNISIG Subset-098 v3.0.0 §6.4.5 and
  Subset-037 v3.2.0 §8.3.2 — streaming encoder/decoder, CRC-CCITT
  validation, AU1/AU2 handshake, DT data transfer, DI disconnect
  (restricted single-link Class D profile).
