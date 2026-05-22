import json
from typing import Any

import pymongo


def parse_json_arg(arg: Any) -> Any:
    if isinstance(arg, str):
        try:
            return json.loads(arg)
        except json.JSONDecodeError:
            return arg
    return arg


def serialize_oid(data: Any) -> Any:
    if isinstance(data, list):
        return [serialize_oid(item) for item in data]
    elif isinstance(data, dict):
        return {k: serialize_oid(v) for k, v in data.items()}
    elif hasattr(data, "__class__") and data.__class__.__name__ == "ObjectId":
        return str(data)
    else:
        return data


class BaseApiClient:
    def __init__(self, client: pymongo.MongoClient):
        self.client = client
