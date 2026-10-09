"""Run the real service (``src.main.main``) with a recording spy on the agent tools' database door.

The offline shadow run of plan C2.5 ("no tool ever issued a write") starts the service as
``python -m tests.e2e.tool_spy_main`` instead of ``python -m src.main``. One thing differs: when the
ADK runtime hands the tools their database (``configure_tools``), that database is wrapped in a spy
that appends every statement and transaction the tools open to the JSON-lines file named by
``TOOL_DB_SPY_LOG`` and then forwards it unchanged. The service's own writers (repository, audit)
keep the real database and are not recorded.
"""

import json
import os


class ToolDatabaseSpy:
    def __init__(self, db, path: str):
        self._db = db
        self._path = path
        self.is_sqlite = getattr(db, "is_sqlite", False)

    def _record(self, statement: str) -> None:
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"statement": statement}) + "\n")

    async def fetch_all(self, query, *args):
        self._record(query)
        return await self._db.fetch_all(query, *args)

    async def fetch_one(self, query, *args):
        self._record(query)
        return await self._db.fetch_one(query, *args)

    async def execute(self, query, *args):
        self._record(query)
        return await self._db.execute(query, *args)

    async def execute_many(self, query, args_list):
        self._record(query)
        return await self._db.execute_many(query, args_list)

    def transaction(self):
        self._record("BEGIN")
        return self._db.transaction()


def install(path: str) -> None:
    from src.investigation.agent import runtime, tools

    original = tools.configure_tools

    def configure_tools_with_spy(deps):
        if deps.db is not None:
            deps.db = ToolDatabaseSpy(deps.db, path)
        original(deps)

    runtime.configure_tools = configure_tools_with_spy


if __name__ == "__main__":
    install(os.environ["TOOL_DB_SPY_LOG"])
    from src.main import main

    main()
