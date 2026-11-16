-- Run as LOGLENS_VECTOR after granting SELECT on LOGLENS_APP.ERROR_KNOWLEDGE.
-- Uses the locally loaded ALL_MINILM_L12_V2 Oracle embedding model.
BEGIN
  EXECUTE IMMEDIATE q'[
    CREATE TABLE error_runbook_vectors (
      error_id       NUMBER PRIMARY KEY,
      technology     VARCHAR2(60) NOT NULL,
      error_code     VARCHAR2(120) NOT NULL,
      title          VARCHAR2(250) NOT NULL,
      description    CLOB NOT NULL,
      likely_causes  CLOB NOT NULL,
      remediation    CLOB NOT NULL,
      verification   CLOB NOT NULL,
      match_terms    CLOB NOT NULL,
      source_url     VARCHAR2(1000),
      chunk_text     CLOB NOT NULL,
      embedding      VECTOR(*, FLOAT32) NOT NULL,
      refreshed_at   TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL
    )
  ]';
EXCEPTION WHEN OTHERS THEN
  IF SQLCODE != -955 THEN RAISE; END IF;
END;
/

CREATE OR REPLACE PROCEDURE refresh_error_runbook_vectors AS
BEGIN
  DELETE FROM error_runbook_vectors;
  COMMIT;

  -- Embed one runbook at a time to keep peak shared-pool usage low on a local
  -- Oracle AI Database Free container.
  FOR runbook IN (
    SELECT error_id, technology, error_code, title, description, likely_causes,
           remediation, verification, match_terms, source_url
    FROM LOGLENS_APP.error_knowledge
    WHERE is_active = 'Y'
    ORDER BY error_id
  ) LOOP
    INSERT INTO error_runbook_vectors (
      error_id, technology, error_code, title, description, likely_causes,
      remediation, verification, match_terms, source_url, chunk_text, embedding
    ) VALUES (
      runbook.error_id, runbook.technology, runbook.error_code, runbook.title,
      runbook.description, runbook.likely_causes, runbook.remediation,
      runbook.verification, runbook.match_terms, runbook.source_url,
      TO_CLOB(runbook.technology || CHR(10) || runbook.error_code || CHR(10) || runbook.title || CHR(10))
        || runbook.description || CHR(10) || runbook.likely_causes || CHR(10)
        || runbook.remediation || CHR(10) || runbook.verification || CHR(10) || runbook.match_terms,
      DBMS_VECTOR_CHAIN.UTL_TO_EMBEDDING(
        TO_CLOB(runbook.technology || CHR(10) || runbook.error_code || CHR(10) || runbook.title || CHR(10))
          || runbook.description || CHR(10) || runbook.likely_causes || CHR(10)
          || runbook.remediation || CHR(10) || runbook.verification || CHR(10) || runbook.match_terms,
        JSON('{"provider":"database", "model":"ALL_MINILM_L12_V2"}')
      )
    );
    COMMIT;
  END LOOP;
END;
/

BEGIN
  refresh_error_runbook_vectors;
END;
/

BEGIN
  EXECUTE IMMEDIATE q'[
    CREATE VECTOR INDEX error_runbook_hnsw_ix ON error_runbook_vectors (embedding)
    ORGANIZATION INMEMORY NEIGHBOR GRAPH DISTANCE COSINE
    WITH TARGET ACCURACY 95
  ]';
EXCEPTION WHEN OTHERS THEN
  -- A small local Docker allocation can lack shared memory for HNSW. The
  -- vector table remains usable through exact similarity search in that case.
  IF SQLCODE NOT IN (-955, -4031, -4033) THEN RAISE; END IF;
END;
/
