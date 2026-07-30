# Compatibility

| SDK | IAM Core baseline | Go | Redis | Notes |
| --- | --- | --- | --- | --- |
| v0.1.x | v1.7.1 runtime contract | 1.24+ | 6.2+, tested 6.2/7.4 | Confidential Client; no PKCE; no organization Claim |

Unknown response fields are tolerated where the protocol permits, and unknown PDP Reason Codes are
preserved. Compatibility does not include IAM Core management APIs or capabilities outside the
documented v0.1 scope.
