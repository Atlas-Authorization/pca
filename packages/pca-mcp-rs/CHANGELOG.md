# Changelog

## 0.4.1 - 2026-10-12

Fixed: `extractPCActn` decodes the `PCA-Action` header with the strict decoder of `@atlasauth/pca` 0.4.1 (`decodePcaHeader`): the value must be unpadded base64url of UTF-8 text, with no surrounding whitespace; padding, the standard alphabet or invalid characters throw (mapped to a 401). Previously it trimmed and decoded leniently.
