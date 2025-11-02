import os

from dotenv import load_dotenv
from fastmcp import Client
import asyncio

load_dotenv()

async def main():
    client = Client("http://127.0.0.1:8088/sse", auth=os.getenv("GITGUARDIAN_PERSONAL_ACCESS_TOKEN"))

    async with client:
        tools = await client.list_tools()
        print(tools)


if __name__ == "__main__":
    asyncio.run(main())