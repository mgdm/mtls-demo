from aiohttp import web
import ssl

PASSPHRASE = "changeit"

async def hello(request):
    return web.Response(text="Hello, world")

app = web.Application()
app.add_routes([web.get('/', hello)])

# Load the server certificate
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.load_cert_chain('ca/server/server.pem', 'ca/server/server.key', PASSPHRASE)

# Set up client certificate authentication
# We want to trust any certificates signed by this CA
ssl_context.load_verify_locations('ca/client/root-ca.pem')
ssl_context.verify_mode = ssl.CERT_REQUIRED

web.run_app(app, port=8443, ssl_context=ssl_context)
