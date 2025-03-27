import asyncio

from .config import config_logging
from .sync import Sync


config_logging()


# start server
async def main():
    s = Sync()
    await s.run()

asyncio.run(main())
