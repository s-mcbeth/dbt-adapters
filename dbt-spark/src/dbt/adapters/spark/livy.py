"""Livy connection integration for dbt-spark with AWS SigV4 authentication."""

from __future__ import annotations

import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
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
        self.signer = crt.auth.CrtS3SigV4Auth(
            self.credentials, self.service, self.region
        )

    def sign_request(
        self, method: str, url: str, data: Optional[Dict] = None
    ) -> requests.PreparedRequest:
        """Signs and prepares a request."""
        headers = {"Content-Type": "application/json"}
        json_data = json.dumps(data) if data else None

        request = AWSRequest(method=method, url=url, data=json_data, headers=headers)
        request.context["payload_signing_enabled"] = False
        self.signer.add_auth(request)
        return request.prepare()


class LivyCursor:
    """Manages statement execution against a Livy session."""

    def __init__(
        self,
        livy_url: str,
        session_id: int,
        auth: CustomSigV4Auth,
        statement_kind: str = "sql",
    ) -> None:
        self.livy_url = livy_url
        self.session_id = session_id
        self.auth = auth
        self.statement_kind = statement_kind
        self._statement_id: Optional[int] = None
        self._rows: Optional[List[Dict[str, Any]]] = None
        self._schema: Optional[List[Tuple[str, str, None, None, None, None, bool]]] = (
            None
        )

    @property
    def description(self) -> Sequence[Tuple[str, Any, ...]]:
        return self._schema or []

    def close(self) -> None:
        self._rows = None
        self._schema = None

    def execute(self, sql: str, bindings: Optional[List[Any]] = None) -> None:
        logger.info(sql)
        if sql.strip().endswith(";"):
            sql = sql.strip()[:-1]

        statement_url = f"{self.livy_url}/sessions/{self.session_id}/statements"
        data = {"code": sql, "kind": self.statement_kind}

        prepped = self.auth.sign_request("POST", statement_url, data)
        response = requests.post(
            prepped.url, headers=prepped.headers, data=prepped.body
        )

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
                raise DbtDatabaseError(
                    f"Failed to get statement status: {response.text}"
                )

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
            (
                field["name"],
                field["type"],
                None,
                None,
                None,
                None,
                field.get("nullable", True),
            )
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

    def __init__(
        self,
        livy_url: str,
        execution_role_arn: str,
        region: str,
        profile_name: Optional[str] = None,
        session_kind: str = "sql",
        spark_conf: Optional[Dict[str, str]] = None,
        job_parameters: Optional[Dict[str, str]] = None,
    ) -> None:
        self.livy_url = livy_url
        self.execution_role_arn = execution_role_arn
        self.region = region
        self.profile_name = profile_name
        self.session_kind = session_kind
        self.spark_conf = spark_conf or {}
        self.job_parameters = job_parameters or {}
        self.auth = CustomSigV4Auth(region=region, profile_name=profile_name)
        self.session_id: Optional[int] = None
        self._cursor: Optional[LivyCursor] = None
        self._is_pooled = False  # Track if this session came from pool
        self._create_session()

    def _create_session(self):
        """Creates a new Livy session and waits for it to become idle."""
        session_url = f"{self.livy_url}/sessions"

        # Start with EMR Serverless execution role
        conf = {"emr-serverless.session.executionRoleArn": self.execution_role_arn}

        # Add any additional Spark configuration
        conf.update(self.spark_conf)

        # Add EMR Serverless job parameters to conf instead of as separate arguments
        if self.job_parameters:
            for k, v in self.job_parameters.items():
                # Convert job parameters to conf format for EMR Serverless
                conf[f"emr-serverless.{k.lstrip('-')}"] = v

        print(conf)

        data = {
            "kind": self.session_kind,
            "conf": conf,
        }
        
        print(f"Livy session creation request data: {data}")
        prepped = self.auth.sign_request("POST", session_url, data)
        response = requests.post(
            prepped.url, headers=prepped.headers, data=prepped.body
        )

        if response.status_code != 201:  # 201 Created
            print(f"Livy session creation failed with status {response.status_code}: {response.text}")
            raise DbtDatabaseError(f"Failed to create Livy session: {response.text}")

        self.session_id = response.json()["id"]
        logger.info(
            f"Livy session created with ID: {self.session_id}. Waiting for it to become idle..."
        )

        session_state_url = f"{self.livy_url}/sessions/{self.session_id}"
        timeout_seconds = 300  # 5 minutes
        start_time = time.time()

        while time.time() - start_time < timeout_seconds:
            prepped_status = self.auth.sign_request("GET", session_state_url)
            status_response = requests.get(
                prepped_status.url, headers=prepped_status.headers
            )

            if status_response.status_code != 200:
                raise DbtDatabaseError(
                    f"Failed to get session status: {status_response.text}"
                )

            session_state = status_response.json().get("state")
            logger.info(f"Livy session {self.session_id} state: {session_state}")

            if session_state == "idle":
                logger.info(
                    f"Livy session {self.session_id} is idle and ready for statements."
                )
                return

            if session_state in ["error", "dead", "killed", "shutting_down"]:
                raise DbtDatabaseError(
                    f"Livy session failed to start. Final state: {session_state}"
                )

            time.sleep(5)  # Poll every 5 seconds

        raise DbtDatabaseError(
            f"Livy session did not become idle within {timeout_seconds} seconds."
        )

    def cursor(self) -> LivyCursor:
        if not self._cursor:
            self._cursor = LivyCursor(
                self.livy_url, self.session_id, self.auth, self.session_kind
            )
        return self._cursor

    def close(self) -> None:
        """Close the session or return it to pool if it was pooled."""
        if self._is_pooled and self.session_id:
            # Return to pool instead of closing
            try:
                pool = LivySessionPool()
                pool.return_session(
                    self,
                    self.livy_url,
                    self.execution_role_arn,
                    self.region,
                    self.profile_name,
                    self.session_kind,
                )
                self._cursor = None  # Clear cursor but keep session_id for pool
                return
            except Exception as e:
                logger.warning(f"Failed to return session to pool: {e}")

        # Actually close the session
        self._close_session()

    def _close_session(self) -> None:
        """Actually close the Livy session without pool logic."""
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
    def rollback(self) -> None:
        pass

    def fetchall(self) -> Optional[List]:
        return None

    def execute(self, sql: str, bindings: Optional[List[Any]] = None) -> None:
        pass

    @property
    def description(self) -> Sequence[Tuple[str, Any, ...]]:
        return self._cursor.description if self._cursor else []


class LivySessionPool:
    """Manages a pool of Livy sessions for reuse to avoid startup delays."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, "_initialized"):
            return
        self._pools: Dict[str, List[LivyConnectionWrapper]] = {}
        self._pool_locks: Dict[str, threading.Lock] = {}
        self._initialized = True
        logger.info("LivySessionPool initialized")

    def _get_pool_key(
        self,
        livy_url: str,
        execution_role_arn: str,
        region: str,
        profile_name: Optional[str],
        session_kind: str,
    ) -> str:
        """Generate a unique key for the session pool."""
        return f"{livy_url}|{execution_role_arn}|{region}|{profile_name}|{session_kind}"

    def get_session(
        self,
        livy_url: str,
        execution_role_arn: str,
        region: str,
        profile_name: Optional[str] = None,
        session_kind: str = "sql",
        spark_conf: Optional[Dict[str, str]] = None,
        job_parameters: Optional[Dict[str, str]] = None,
    ) -> LivyConnectionWrapper:
        """Get a session from the pool or create a new one."""
        pool_key = self._get_pool_key(
            livy_url, execution_role_arn, region, profile_name, session_kind
        )

        # Ensure pool and lock exist for this key
        if pool_key not in self._pools:
            with self._lock:
                if pool_key not in self._pools:
                    self._pools[pool_key] = []
                    self._pool_locks[pool_key] = threading.Lock()

        # Try to get existing session from pool
        with self._pool_locks[pool_key]:
            if self._pools[pool_key]:
                session = self._pools[pool_key].pop()
                session._is_pooled = True  # Mark as pooled
                logger.info(f"Reusing existing Livy session {session.session_id}")
                return session

        # No sessions available, create new one
        logger.info(f"Creating new Livy session with kind: {session_kind}")
        session = LivyConnectionWrapper(
            livy_url,
            execution_role_arn,
            region,
            profile_name,
            session_kind,
            spark_conf,
            job_parameters,
        )
        session._is_pooled = True  # Mark new sessions as pooled too
        return session

    def return_session(
        self,
        session: LivyConnectionWrapper,
        livy_url: str,
        execution_role_arn: str,
        region: str,
        profile_name: Optional[str] = None,
        session_kind: str = "sql",
    ) -> None:
        """Return a session to the pool for reuse."""
        pool_key = self._get_pool_key(
            livy_url, execution_role_arn, region, profile_name, session_kind
        )

        if pool_key not in self._pools:
            # Pool doesn't exist, just close the session
            session._close_session()
            return

        with self._pool_locks[pool_key]:
            # Only keep a reasonable number of sessions in pool
            if len(self._pools[pool_key]) < 3:  # Max 3 sessions per pool
                self._pools[pool_key].append(session)
                logger.info(f"Returned Livy session {session.session_id} to pool")
            else:
                session._close_session()
                logger.info(f"Pool full, closed Livy session {session.session_id}")

    def warm_up_sessions(
        self,
        livy_url: str,
        execution_role_arn: str,
        region: str,
        profile_name: Optional[str] = None,
        spark_conf: Optional[Dict[str, str]] = None,
        job_parameters: Optional[Dict[str, str]] = None,
        sql_sessions: int = 2,
        pyspark_sessions: int = 1,
    ) -> None:
        """Pre-create sessions in parallel to avoid startup delays."""
        logger.info(
            f"Warming up {sql_sessions} SQL and {pyspark_sessions} PySpark sessions..."
        )

        def create_session(session_kind: str) -> LivyConnectionWrapper:
            try:
                session = LivyConnectionWrapper(
                    livy_url,
                    execution_role_arn,
                    region,
                    profile_name,
                    session_kind,
                    spark_conf,
                    job_parameters,
                )
                session._is_pooled = True  # Mark warm-up sessions as pooled
                return session
            except Exception as e:
                logger.error(f"Failed to create {session_kind} session: {e}")
                return None

        with ThreadPoolExecutor(
            max_workers=sql_sessions + pyspark_sessions
        ) as executor:
            # Submit session creation tasks
            futures = []

            # Create SQL sessions
            for _ in range(sql_sessions):
                futures.append(executor.submit(create_session, "sql"))

            # Create PySpark sessions
            for _ in range(pyspark_sessions):
                futures.append(executor.submit(create_session, "pyspark"))

            # Collect completed sessions and add to pools directly
            for future in as_completed(futures):
                session = future.result()
                if session:
                    # Add directly to pool to avoid recursion issues
                    pool_key = self._get_pool_key(
                        livy_url,
                        execution_role_arn,
                        region,
                        profile_name,
                        session.session_kind,
                    )

                    # Ensure pool exists
                    if pool_key not in self._pools:
                        with self._lock:
                            if pool_key not in self._pools:
                                self._pools[pool_key] = []
                                self._pool_locks[pool_key] = threading.Lock()

                    # Add to pool directly
                    with self._pool_locks[pool_key]:
                        self._pools[pool_key].append(session)
                        logger.info(
                            f"Added warm-up session {session.session_id} to pool"
                        )

        logger.info("Session warm-up completed")

    def close_all_sessions(self) -> None:
        """Close all pooled sessions."""
        with self._lock:
            for pool_key, sessions in self._pools.items():
                with self._pool_locks[pool_key]:
                    for session in sessions:
                        try:
                            session._close_session()
                        except Exception as e:
                            logger.warning(f"Error closing session: {e}")
                    sessions.clear()
        logger.info("All pooled sessions closed")
