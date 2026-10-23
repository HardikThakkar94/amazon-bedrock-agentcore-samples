"""TicketTools: the AgentCore Gateway Lambda target behind the support agent.

Three tools over the DynamoDB ticket table: ``list_tickets``, ``close_ticket`` and ``add_note``.
The Gateway passes the tool arguments as the event and the tool name (``TicketTools___<tool>``)
in the client context. Every call carries ``actor`` (the signed-in user's ``user_sub`` and
``customer_id``), set by the agent's runtime from the verified token, never by the model.

This function deliberately does no authorization of its own: which calls may reach it is the
Gateway's job (AgentCore Policy, per build). In the V0 build nothing stands in between.
"""

from __future__ import annotations

import os
import time
from typing import Any

MAX_NOTE = 500
_table = None


def table():
    global _table
    if _table is None:
        import boto3

        _table = boto3.resource("dynamodb").Table(os.environ["TICKETS_TABLE"])
    return _table


def tool_name(context: Any) -> str:
    custom = getattr(getattr(context, "client_context", None), "custom", None) or {}
    return custom.get("bedrockAgentCoreToolName", "").split("___")[-1]


def actor_of(event: dict[str, Any]) -> dict[str, str]:
    actor = event.get("actor") or {}
    return {
        "user_sub": str(actor.get("user_sub", "")),
        "customer_id": str(actor.get("customer_id", "")),
    }


def list_tickets(tbl, event: dict[str, Any]) -> dict[str, Any]:
    customer_id = str(event.get("customer_id", ""))
    items = tbl.query(
        KeyConditionExpression="customer_id = :c",
        ExpressionAttributeValues={":c": customer_id},
    )["Items"]
    tickets = [
        {
            "ticket_id": t["ticket_id"],
            "customer_id": t["customer_id"],
            "subject": t.get("subject", ""),
            "body": t.get("body", ""),
            "status": t.get("status", "OPEN"),
            "submitted_by": t.get("submitted_by", "customer"),
            "notes": list(t.get("notes", [])),
        }
        for t in sorted(items, key=lambda t: t["ticket_id"])
    ]
    return {"customer_id": customer_id, "ticket_count": len(tickets), "tickets": tickets}


def close_ticket(tbl, event: dict[str, Any]) -> dict[str, Any]:
    key = {
        "customer_id": str(event.get("customer_id", "")),
        "ticket_id": str(event.get("ticket_id", "")),
    }
    item = tbl.get_item(Key=key).get("Item")
    if item is None:
        return {**key, "status": "TARGET_NOT_FOUND"}
    if item.get("status") == "CLOSED":
        return {**key, "status": "ALREADY_CLOSED"}
    tbl.update_item(
        Key=key,
        UpdateExpression="SET #s = :closed, closed_by = :by, closed_reason = :why, closed_at = :at",
        ConditionExpression="#s <> :closed",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":closed": "CLOSED",
            ":by": actor_of(event),
            ":why": str(event.get("reason", ""))[:MAX_NOTE],
            ":at": int(time.time()),
        },
    )
    return {**key, "status": "CLOSED"}


def add_note(tbl, event: dict[str, Any]) -> dict[str, Any]:
    key = {
        "customer_id": str(event.get("customer_id", "")),
        "ticket_id": str(event.get("ticket_id", "")),
    }
    note = str(event.get("note", "")).strip()[:MAX_NOTE]
    if not note:
        return {**key, "status": "EMPTY_NOTE"}
    if tbl.get_item(Key=key).get("Item") is None:
        return {**key, "status": "TARGET_NOT_FOUND"}
    tbl.update_item(
        Key=key,
        UpdateExpression="SET notes = list_append(if_not_exists(notes, :none), :note)",
        ExpressionAttributeValues={":none": [], ":note": [{"by": actor_of(event), "text": note}]},
    )
    return {**key, "status": "NOTED"}


TOOLS = {"list_tickets": list_tickets, "close_ticket": close_ticket, "add_note": add_note}


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    handler = TOOLS.get(tool_name(context))
    if handler is None:
        return {"status": "UNKNOWN_TOOL"}
    return handler(table(), event or {})
