"""Back-compat shim: the ingest connectors live in the core package (luretrace.ingest)."""
from luretrace.ingest import *  # noqa: F401,F403
from luretrace.ingest import (  # noqa: F401
    CONNECTORS,
    Connector,
    DataLakeConnector,
    IngestItem,
    MimecastConnector,
    build_connector,
)
