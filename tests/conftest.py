import os
import tempfile

import pytest

# Point the app at a throwaway database *before* anything imports settings.
_tmp = tempfile.mkdtemp(prefix="tw-test-")
os.environ["TW_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["TW_SCHEDULER_ENABLED"] = "false"
os.environ["TW_ALERT_WEBHOOK_URL"] = ""
os.environ["TW_API_KEY"] = ""
os.environ["TW_PENTEST_ENABLED"] = "false"  # pin off so a developer's local .env can't flip it on in tests
os.environ["TW_DATA_DIR"] = _tmp

from threatwatch.config import get_settings  # noqa: E402
from threatwatch.db import Base, create_all, get_engine, init_engine, session_scope  # noqa: E402

get_settings.cache_clear()
init_engine(os.environ["TW_DATABASE_URL"])
create_all()


@pytest.fixture()
def db():
    """Clean database for each test that asks for it."""
    engine = get_engine()
    with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())
    with session_scope() as s:
        yield s


@pytest.fixture()
def client(db):
    from fastapi.testclient import TestClient

    from threatwatch.main import create_app

    with TestClient(create_app(start_scheduler=False)) as c:
        yield c
