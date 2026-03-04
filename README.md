This is a quick demo of using client certificate authentication in `aiohttp`.

I set this up using `uv`, so to do as I did, follow the commands below, but you can use `pip` or whatever to install `cryptography` and `aiohttp`.

## With `uv`

```bash

# Generate the server CA if you need one
# In production this will be handled by something like LetsEncrypt
# The generated leaf certificate will be for `localhost`
uv run python generate-server-ca.py

# Generate the client CA
uv run python generate-client-ca.py


# Run the server - defaults to localhost:8443
uv run server/server.py

# In another terminal
uv run client/client.py
```

## Otherwise

```bash
python generate-server-ca.py
python generate-client-ca.py

server/server.py

# In another terminal
client/client.py
```

## curl

```bash
curl --cert ca/client/client.pem --key ca/client/client.key --cacert ca/server/root-ca.pem --pass changeit https://localhost:8443
```
