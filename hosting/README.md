# Inkos hosted integration — development checkpoint

These broker and worker sources are an AI-assisted, incomplete development checkpoint.
They are not deployed or accepted for public use. Do not expose raw Studio.

Each tenant requires a networkless container with only its own project/HOME/runtime mounts. The broker binds users to original new-api sessions and each user's own finite token. The broker never receives a Docker socket. Protocol tests contain explicit test doubles and do not prove real model billing or production isolation.

Complete two-user, logout/revocation, finite-token billing, persistence and rollback acceptance before marking a version releasable. Preserve the upstream AGPL license; no credentials, tenant content, runtime sockets or deployment environment files are included.
