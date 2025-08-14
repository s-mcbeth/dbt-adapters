"""Livy connection integration for dbt-spark with AWS SigV4 authentication."""

from __future__ import annotations

import json
import time
from types import TracebackType
from typing import Any, Dict, List, Optional, Sequence, Tuple

import botocore.session
import requests
from botocore.awsrequest import AWSRequest
from botocore import crt

from dbt.adapters.events.logging import AdapterLogger
from dbt.adapters.spark.connections import SparkConnectionWrapper
from dbt_common.exceptions import DbtDatabaseError

logger = AdapterLogger("Spark")


class CustomSigV4Auth:
    """Signs HTTP requests using AWS Signature Version 4."""

    def __init__(self, region: str, profile_name: Optional[str] = None):
        self.session = botocore.session.Session(profile=profile_name)
        self.credentials = self.session.get_credentials()
        self.region = region
        self.service = "emr-serverless"
        self.signer = crt.auth.CrtS3SigV4Auth(self.credentials, self.service, self.region)

    def sign_request(self, method: str, url: str, data: Optional[Dict] = None) -> requests.PreparedRequest:
        """Signs and prepares a request."""
        headers = {"Content-Type": "application/json"}
        json_data = json.dumps(data) if data else None

        request = AWSRequest(method=method, url=url, data=json_data, headers=headers)
        request.context["payload_signing_enabled"] = False
        self.signer.add_auth(request)
        return request.prepare()


class LivyCursor:
    """Manages statement execution against a Livy session."""

    def __init__(self, livy_url: str, session_id: int, auth: CustomSigV4Auth) -> None:
        self.livy_url = livy_url
        self.session_id = session_id
        self.auth = auth
        self._statement_id: Optional[int] = None
        self._rows: Optional[List[Dict[str, Any]]] = None
        self._schema: Optional[List[Tuple[str, str, None, None, None, None, bool]]] = None

    @property
    def description(self) -> Sequence[Tuple[str, Any, ...]]:
        return self._schema or []

    def close(self) -> None:
        self._rows = None
        self._schema = None

    def execute(self, sql: str, bindings: Optional[List[Any]] = None) -> None:
        if sql.strip().endswith(";"):
            sql = sql.strip()[:-1]

        statement_url = f"{self.livy_url}/sessions/{self.session_id}/statements"
        data = {"code": sql, "kind": "sql"}

        prepped = self.auth.sign_request("POST", statement_url, data)
        response = requests.post(prepped.url, headers=prepped.headers, data=prepped.body)

        if response.status_code != 201:  # Livy returns 201 Created
            raise DbtDatabaseError(f"Failed to execute statement: {response.text}")

        self._statement_id = response.json()["id"]
        self._poll_for_completion()

    def _poll_for_completion(self):
        """Polls Livy for statement completion and fetches results."""
        statement_url = f"{self.livy_url}/sessions/{self.session_id}/statements/{self._statement_id}"
        while True:
            prepped = self.auth.sign_request("GET", statement_url)
            response = requests.get(prepped.url, headers=prepped.headers)

            if response.status_code != 200:
                raise DbtDatabaseError(f"Failed to get statement status: {response.text}")

            status = response.json()
            state = status["state"]

            if state == "available":
                output = status.get("output", {})
                if output.get("status") == "ok":
                    self._parse_results(output.get("data", {}))
                else:
                    error_msg = output.get("evalue", "Unknown error")
                    raise DbtDatabaseError(f"Statement failed: {error_msg}")
                break
            elif state in ["error", "cancelled", "cancelling"]:
                raise DbtDatabaseError(f"Statement failed with state: {state}")

            time.sleep(1)

    def _parse_results(self, data: Dict) -> None:
        """Parses Livy's JSON output into a schema and rows."""
        if not data or "application/json" not in data:
            self._schema = []
            self._rows = []
            return

        table_data = data["application/json"]
        self._schema = [
            (field["name"], field["type"], None, None, None, None, field.get("nullable", True))
            for field in table_data.get("schema", {}).get("fields", [])
        ]
        self._rows = table_data.get("data", [])

    def fetchall(self) -> List[Dict[str, Any]]:
        return self._rows or []

    def cancel(self) -> None:
        if self._statement_id:
            cancel_url = f"{self.livy_url}/sessions/{self.session_id}/statements/{self._statement_id}/cancel"
            prepped = self.auth.sign_request("POST", cancel_url)
            requests.post(prepped.url, headers=prepped.headers)


class LivyConnectionWrapper(SparkConnectionWrapper):
    """Wraps a Livy session and handles its lifecycle."""

    def __init__(self, livy_url: str, execution_role_arn: str, region: str, profile_name: Optional[str] = None) -> None:
        self.livy_url = livy_url
        self.execution_role_arn = execution_role_arn
        self.auth = CustomSigV4Auth(region=region, profile_name=profile_name)
        self.session_id: Optional[int] = None
        self._cursor: Optional[LivyCursor] = None
        self._create_session()

    def _create_session(self):
        """Creates a new Livy session and waits for it to become idle."""
        session_url = f"{self.livy_url}/sessions"
        data = {
            "kind": "sql",
            "conf": {"emr-serverless.session.executionRoleArn": self.execution_role_arn},
        }
        prepped = self.auth.sign_request("POST", session_url, data)
        response = requests.post(prepped.url, headers=prepped.headers, data=prepped.body)

        if response.status_code != 201:  # 201 Created
            raise DbtDatabaseError(f"Failed to create Livy session: {response.text}")
        
        self.session_id = response.json()["id"]
        logger.info(f"Livy session created with ID: {self.session_id}. Waiting for it to become idle...")

        session_state_url = f"{self.livy_url}/sessions/{self.session_id}"
        timeout_seconds = 300  # 5 minutes
        start_time = time.time()

        while time.time() - start_time < timeout_seconds:
            prepped_status = self.auth.sign_request("GET", session_state_url)
            status_response = requests.get(prepped_status.url, headers=prepped_status.headers)

            if status_response.status_code != 200:
                raise DbtDatabaseError(f"Failed to get session status: {status_response.text}")

            session_state = status_response.json().get("state")
            logger.info(f"Livy session {self.session_id} state: {session_state}")

            if session_state == "idle":
                logger.info(f"Livy session {self.session_id} is idle and ready for statements.")
                return
            
            if session_state in ["error", "dead", "killed", "shutting_down"]:
                raise DbtDatabaseError(f"Livy session failed to start. Final state: {session_state}")

            time.sleep(5)  # Poll every 5 seconds

        raise DbtDatabaseError(f"Livy session did not become idle within {timeout_seconds} seconds.")

    def cursor(self) -> LivyCursor:
        if not self._cursor:
            self._cursor = LivyCursor(self.livy_url, self.session_id, self.auth)
        return self._cursor

    def close(self) -> None:
        if self.session_id:
            session_url = f"{self.livy_url}/sessions/{self.session_id}"
            prepped = self.auth.sign_request("DELETE", session_url)
            requests.delete(prepped.url, headers=prepped.headers)
            self.session_id = None
        self._cursor = None

    def cancel(self) -> None:
        if self._cursor:
            self._cursor.cancel()
            
    # Add dummy methods to satisfy the abstract base class
    def rollback(self) -> None: pass
    def fetchall(self) -> Optional[List]: return None
    def execute(self, sql: str, bindings: Optional[List[Any]] = None) -> None: pass
    
    @property
    def description(self) -> Sequence[Tuple[str, Any, ...]]:
        return self._cursor.description if self._cursor else []
