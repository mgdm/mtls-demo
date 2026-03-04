import aiohttp
import asyncio
import ssl

PASSPHRASE = "changeit"

ssl_context = ssl.create_default_context()

# Load the client certiificate
ssl_context.load_cert_chain("ca/client/client.pem",
                            "ca/client/client.key",
                            PASSPHRASE)

# Load the CA for the server
ssl_context.load_verify_locations("ca/server/root-ca.pem")

async def main():
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
        async with session.get('https://localhost:8443') as resp:
            print(resp.status)
            print(await resp.text())

asyncio.run(main())

