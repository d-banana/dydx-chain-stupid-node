```mermaid
graph TD
    1[Connection to a new pair] --> 2[Initialized];
    2 --> 3[Ephemeral ED25519 verifying local key sent];
    3 --> 4[Ephemeral ED25519 verifying remote key received];
```