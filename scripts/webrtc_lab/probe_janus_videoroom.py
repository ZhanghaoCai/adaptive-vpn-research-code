#!/usr/bin/env python3
"""Print the Janus VideoRoom create exchange for protocol compatibility checks."""

from __future__ import annotations

import asyncio
import json
import secrets
import time

import websockets


async def exchange() -> None:
    async with websockets.connect(
        "ws://127.0.0.1:8188/", subprotocols=["janus-protocol"]
    ) as socket:
        transaction = secrets.token_hex(6)
        await socket.send(json.dumps({"janus": "create", "transaction": transaction}))
        created = json.loads(await socket.recv())
        print(json.dumps(created, sort_keys=True))
        session_id = created["data"]["id"]

        transaction = secrets.token_hex(6)
        await socket.send(
            json.dumps(
                {
                    "janus": "attach",
                    "plugin": "janus.plugin.videoroom",
                    "session_id": session_id,
                    "transaction": transaction,
                }
            )
        )
        attached = json.loads(await socket.recv())
        print(json.dumps(attached, sort_keys=True))
        handle_id = attached["data"]["id"]

        transaction = secrets.token_hex(6)
        await socket.send(
            json.dumps(
                {
                    "janus": "message",
                    "session_id": session_id,
                    "handle_id": handle_id,
                    "transaction": transaction,
                    "body": {
                        "request": "create",
                        "room": int(str(time.time_ns())[-8:]),
                        "description": "bounded-avpn-webrtc-lab",
                        "publishers": 2,
                        "permanent": False,
                    },
                }
            )
        )
        for _ in range(3):
            try:
                response = await asyncio.wait_for(socket.recv(), timeout=3)
            except TimeoutError:
                break
            print(json.dumps(json.loads(response), sort_keys=True))


if __name__ == "__main__":
    asyncio.run(exchange())
