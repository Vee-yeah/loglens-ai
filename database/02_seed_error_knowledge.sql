-- Re-runnable starter runbooks. Add reviewed records for your organisation's systems.
MERGE INTO error_knowledge target
USING (
    SELECT 'Oracle SQL/PLSQL' technology, 'ORA-00001' error_code, 'Unique constraint violated' title,
           'An insert or update conflicts with an existing unique value.' description,
           'Duplicate request, non-idempotent retry, or an existing business key.' likely_causes,
           'Resolve the exact owner.constraint through ALL_CONS_COLUMNS, then make the write idempotent or correct the conflicting data.' remediation,
           'Re-run the transaction and confirm only one record exists for the business key.' verification,
           'ORA-00001|unique constraint|unique constraint violated' match_terms,
           'https://docs.oracle.com/error-help/db/ora-00001/' source_url
    FROM dual
    UNION ALL SELECT 'Oracle SQL/PLSQL', 'ORA-00942', 'Table or view does not exist',
           'The SQL cannot resolve a required table or view, or the runtime schema lacks a direct privilege.',
           'Missing migration, wrong schema/synonym, or missing direct SELECT/EXECUTE grant in definer-rights PL/SQL.',
           'Use ALL_SOURCE at the ORA-06512 line to identify the object, then verify schema, synonym, deployment, and direct privilege.',
           'Execute the failing package with the runtime schema and confirm the object resolves.' ,
           'ORA-00942|table or view does not exist|ORA-06512',
           'https://docs.oracle.com/error-help/db/ora-00942/' FROM dual
    UNION ALL SELECT 'Java/JVM', 'NullPointerException', 'Null reference',
           'Code dereferenced an uninitialised Java object.',
           'Unexpected null input, absent dependency response, or missing optional field.',
           'Use the first application stack frame to validate the object before dereference and add a meaningful guard or default.',
           'Add a test for the null input and confirm the request now returns a controlled response.',
           'NullPointerException|Cannot invoke', NULL FROM dual
    UNION ALL SELECT 'Java/JVM', 'ConnectException', 'Connection refused',
           'The target process did not accept a TCP connection.',
           'Target service down, wrong host/port, or blocked network path.',
           'Verify DNS, configured host/port, target health, service listener, and firewall policy.',
           'Connect from the application network and verify a successful health endpoint response.',
           'ConnectException|Connection refused', NULL FROM dual
    UNION ALL SELECT 'Python', 'KeyError', 'Missing dictionary key',
           'Python attempted to access a dictionary key that was absent.',
           'Unexpected payload shape, optional field, or an upstream contract change.',
           'Validate the incoming payload and use an explicit key-existence check or a safe default where appropriate.',
           'Add a test with the missing field and verify error handling is intentional.',
           'KeyError|missing dictionary key', NULL FROM dual
    UNION ALL SELECT 'Python', 'ModuleNotFoundError', 'Python module missing',
           'A required Python dependency is absent from the active virtual environment or deployed artifact.',
           'Dependency not declared, wrong interpreter, or incomplete deployment package.',
           'Add the package to requirements, rebuild the environment, and verify the deployed interpreter.',
           'Import the module in the deployed environment and run the failing job.',
           'ModuleNotFoundError|ImportError|No module named', NULL FROM dual
    UNION ALL SELECT 'PostgreSQL', '23505', 'Unique violation',
           'A write conflicts with an existing PostgreSQL unique key.',
           'Duplicate event delivery, retry without idempotency, or incorrect key generation.',
           'Use the constraint, columns, and conflicting values from the error detail to locate the row; make writes idempotent.',
           'Repeat the request and verify no duplicate row is created.',
           '23505|duplicate key value|unique constraint', NULL FROM dual
    UNION ALL SELECT 'HTTP/API', 'HTTP 401', 'Authentication failure',
           'The server rejected the presented authentication credentials.',
           'Expired token, incorrect audience, missing scope, or wrong identity provider.',
           'Inspect token expiry, audience, configured issuer, and required scopes without logging secret values.',
           'Obtain a new authorized token and verify the endpoint responds successfully.',
           'HTTP 401|Unauthorized|invalid token', NULL FROM dual
) source
ON (target.technology = source.technology AND target.error_code = source.error_code)
WHEN MATCHED THEN UPDATE SET
    target.title = source.title, target.description = source.description,
    target.likely_causes = source.likely_causes, target.remediation = source.remediation,
    target.verification = source.verification, target.match_terms = source.match_terms,
    target.source_url = source.source_url, target.updated_at = SYSTIMESTAMP
WHEN NOT MATCHED THEN INSERT (
    technology, error_code, title, description, likely_causes, remediation,
    verification, match_terms, source_url
) VALUES (
    source.technology, source.error_code, source.title, source.description,
    source.likely_causes, source.remediation, source.verification,
    source.match_terms, source.source_url
);

COMMIT;
