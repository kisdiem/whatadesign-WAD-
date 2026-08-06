NODE_TYPE_VOCAB = {name: i for i, name in enumerate(("event", "user", "host", "process", "file", "ip", "domain", "port", "service", "session", "registry", "container", "cloud_resource", "unknown"))}
EDGE_ROLE_VOCAB = {name: i for i, name in enumerate(("actor_of", "source_host_of", "process_of", "object_of", "destination_of", "parent_process_of", "session_of"))}
ACTION_VOCAB = {name: i for i, name in enumerate(("unknown", "read", "write", "execute", "authenticate", "connect", "create", "delete"))}
OUTCOME_VOCAB = {name: i for i, name in enumerate(("unknown", "success", "failure"))}
