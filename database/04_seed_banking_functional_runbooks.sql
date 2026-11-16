-- Fictional banking-domain RAG runbooks for LogLens demonstrations.
-- The schemas, tables, service names, and queue names below are examples only.
-- Replace them with approved organisation-specific names before production use.
MERGE INTO error_knowledge target
USING (
    SELECT 'Banking / Accounts' technology, 'BANK_ACCOUNT_NOT_FOUND' error_code, 'Bank account not found' title,
           'The requested account identifier could not be resolved by the core-account service.' description,
           'Invalid account number, account held in a different tenant, delayed account onboarding, or a stale channel cache.' likely_causes,
           'Trace the correlation ID through AccountService. Check BANK_CORE.ACCOUNT_MASTER for the masked account reference and tenant; check BANK_CORE.ACCOUNT_STATUS_HISTORY for closure or migration events. Correct the channel mapping or complete the onboarding event; do not create a replacement account to bypass the error.' remediation,
           'Call AccountService using the approved masked reference and confirm the expected account status is returned.' verification,
           'bank account not found|account not found|account does not exist|invalid account number' terms FROM dual
    UNION ALL SELECT 'Banking / Accounts', 'BANK_BALANCE_UNAVAILABLE', 'Balance not available',
           'The system could not provide a current available or ledger balance.' ,
           'Balance cache is stale, ledger posting is delayed, AccountBalanceService is unavailable, or an account is under reconciliation.',
           'Check BalanceService health and the last refresh in BANK_CORE.ACCOUNT_BALANCE. Compare available_balance and ledger_balance with LEDGER.GL_POSTING for the correlation ID. Repair the delayed posting or cache refresh through the approved reconciliation workflow; never alter balance values directly.',
           'The balance endpoint returns a timestamped available and ledger balance that reconciles with the ledger.',
           'balance not available|balance unavailable|unable to retrieve balance|balance service unavailable' FROM dual
    UNION ALL SELECT 'Banking / Payments', 'BANK_INSUFFICIENT_FUNDS', 'Insufficient available balance',
           'A debit or transfer exceeds the account available balance after holds and pending debits.',
           'Insufficient funds, pending card authorisation hold, debit limit, or a stale channel balance.',
           'Inspect the transaction in PAYMENTS.PAYMENT_TRANSACTION and active holds in BANK_CORE.ACCOUNT_HOLD. Recalculate available balance from BANK_CORE.ACCOUNT_BALANCE and approved pending entries. Explain the valid hold or request customer funding; do not override limits outside the authorised exception process.',
           'Re-submit only after available balance covers the amount and the transaction is authorised once.',
           'insufficient funds|insufficient balance|available balance exceeded|debit declined' FROM dual
    UNION ALL SELECT 'Banking / Accounts', 'BANK_ACCOUNT_BLOCKED', 'Account blocked or frozen',
           'The account is not permitted to process the requested operation.',
           'Fraud hold, compliance restriction, customer request, court order, or operational freeze.',
           'Check BANK_CORE.ACCOUNT_STATUS_HISTORY and RISK.ACCOUNT_RESTRICTION using the correlation ID. Identify the restriction owner and follow the approved fraud, compliance, or operations release process. Do not remove a freeze directly from application tables.',
           'AccountService reports an allowed status after the authorised team records the release.',
           'account blocked|account frozen|account restricted|debit not allowed' FROM dual
    UNION ALL SELECT 'Banking / Accounts', 'BANK_ACCOUNT_INACTIVE', 'Account closed or dormant',
           'The requested transaction cannot be processed because the account is closed, dormant, or inactive.',
           'Customer closure, dormancy policy, product migration, or incorrect account-status synchronisation.',
           'Review BANK_CORE.ACCOUNT_MASTER.account_status and BANK_CORE.ACCOUNT_STATUS_HISTORY. Validate the effective date and channel policy in AccountService. Route reactivation or product-migration actions through the approved servicing workflow.',
           'The status returned by AccountService matches the authorised account lifecycle state.',
           'account closed|account dormant|account inactive|account status invalid' FROM dual
    UNION ALL SELECT 'Banking / Payments', 'BANK_DUPLICATE_TRANSACTION', 'Duplicate payment request',
           'The same business payment appears more than once or an idempotency key was re-used.',
           'Client retry after timeout, duplicate queue delivery, replayed API request, or missing idempotency enforcement.',
           'Search PAYMENTS.PAYMENT_TRANSACTION by client_request_id, idempotency_key, amount, and masked account. Inspect PAYMENTS.PAYMENT_EVENT and queue PAYMENT_EVENTS for duplicate delivery. Preserve one authoritative transaction and use the approved reversal workflow for any duplicate posting.',
           'A retry with the same idempotency key returns the original transaction outcome and produces no new posting.',
           'duplicate transaction|duplicate payment|idempotency key|payment already processed' FROM dual
    UNION ALL SELECT 'Banking / Payments', 'BANK_TRANSACTION_NOT_FOUND', 'Payment transaction not found',
           'A payment reference cannot be located by the payments service.',
           'Incorrect reference, delayed event ingestion, wrong environment, archival boundary, or failed transaction creation.',
           'Search PAYMENTS.PAYMENT_TRANSACTION and PAYMENTS.PAYMENT_EVENT by correlation ID and client reference. Check PaymentOrchestrator logs and PAYMENT_EVENTS dead-letter queue. Correct the reference or replay only an approved, idempotent event.',
           'The transaction is visible with a traceable lifecycle or the caller receives a controlled not-found response.',
           'transaction not found|payment not found|invalid transaction reference|transfer reference not found' FROM dual
    UNION ALL SELECT 'Banking / Payments', 'BANK_TRANSACTION_PENDING', 'Payment remains pending',
           'A payment has not reached a terminal success, failure, return, or reversal state within its expected SLA.',
           'Awaiting external switch response, ledger posting delay, queue backlog, manual review, or callback failure.',
           'Check PAYMENTS.PAYMENT_TRANSACTION.status and PAYMENTS.PAYMENT_EVENT timeline. Correlate with PaymentOrchestrator, external-switch adapter, and LEDGER.GL_POSTING. Process the pending item through the documented timeout/reconciliation workflow; do not re-submit blindly.',
           'The payment reaches exactly one terminal state and the ledger reflects that state.',
           'transaction pending|payment pending|transfer pending|awaiting settlement' FROM dual
    UNION ALL SELECT 'Banking / Payments', 'BANK_TRANSACTION_FAILED', 'Payment processing failed',
           'A payment reached a failure state before settlement.',
           'Validation failure, external payment network decline, internal service fault, or ledger-posting failure.',
           'Read the failure code and correlation ID in PAYMENTS.PAYMENT_TRANSACTION and PAYMENT_EVENTS. Check the failing adapter or downstream service and whether a compensating ledger event was produced. Fix the confirmed dependency or data issue before a controlled retry.',
           'A retry or correction produces one successful terminal transaction with no duplicate ledger entry.',
           'transaction failed|payment failed|transfer failed|payment processing error' FROM dual
    UNION ALL SELECT 'Banking / Payments', 'BANK_REVERSAL_REQUIRED', 'Payment reversal required',
           'A completed debit or credit needs an authorised compensating reversal.',
           'Duplicate payment, downstream rejection after posting, disputed transaction, or settlement exception.',
           'Validate the original event in PAYMENTS.PAYMENT_TRANSACTION, associated ledger rows in LEDGER.GL_POSTING, and reversal eligibility. Submit a compensating event through ReversalService with the original transaction reference; never manually delete financial postings.',
           'The original and reversal are linked, net to the expected balance, and are visible in the audit trail.',
           'reversal required|reverse transaction|payment reversal|compensating transaction' FROM dual
    UNION ALL SELECT 'Banking / Beneficiary', 'BANK_BENEFICIARY_NOT_FOUND', 'Beneficiary not found',
           'The transfer beneficiary cannot be resolved for the customer or payment route.',
           'Incorrect beneficiary identifier, deleted beneficiary, unsynchronised onboarding, or tenant mismatch.',
           'Check PAYMENTS.BENEFICIARY_MASTER and PAYMENTS.BENEFICIARY_AUDIT using the masked beneficiary reference. Verify ownership and verification status in BeneficiaryService, then complete approved beneficiary registration if required.',
           'BeneficiaryService returns an active, verified beneficiary for the requesting customer.',
           'beneficiary not found|payee not found|recipient not found' FROM dual
    UNION ALL SELECT 'Banking / Beneficiary', 'BANK_BENEFICIARY_UNVERIFIED', 'Beneficiary verification incomplete',
           'The beneficiary exists but cannot receive payment until verification completes.',
           'Pending verification, failed account validation, sanctions screening hold, or expired verification evidence.',
           'Review PAYMENTS.BENEFICIARY_MASTER.verification_status and the related RISK.SCREENING_RESULT. Resolve the failed validation with the authorised operations workflow; do not mark a beneficiary verified directly in the database.',
           'The beneficiary has an approved verification state and the transfer passes validation.',
           'beneficiary not verified|beneficiary verification pending|payee verification failed' FROM dual
    UNION ALL SELECT 'Banking / Limits', 'BANK_TRANSACTION_LIMIT_EXCEEDED', 'Transaction limit exceeded',
           'The requested amount, count, or velocity exceeds a configured customer, account, product, or channel limit.',
           'Daily limit used, per-transaction cap, fraud velocity rule, currency limit, or stale limit cache.',
           'Inspect LIMITS.CUSTOMER_LIMIT_USAGE and LIMITS.LIMIT_POLICY with the correlation ID, product, channel, and currency. Validate the applicable policy version and refresh cache if authorised. Request a formal limit change rather than bypassing a rule.',
           'The transaction is accepted only when it complies with the currently approved limit policy.',
           'transaction limit exceeded|daily limit exceeded|transfer limit exceeded|limit exceeded' FROM dual
    UNION ALL SELECT 'Banking / Compliance', 'BANK_KYC_INCOMPLETE', 'KYC or customer verification incomplete',
           'The requested operation is restricted because customer due-diligence requirements are incomplete or expired.',
           'Missing documents, expired KYC review, failed identity check, or risk-rating restriction.',
           'Check CUSTOMER.KYC_PROFILE and RISK.KYC_REVIEW_TASK for the masked customer ID. Identify the missing or expired requirement and route it to the approved KYC workflow. Do not override compliance state in application data.',
           'KYC status is approved by the compliance workflow and the permitted transaction succeeds.',
           'kyc incomplete|kyc expired|customer verification failed|identity verification required' FROM dual
    UNION ALL SELECT 'Banking / Ledger', 'BANK_LEDGER_MISMATCH', 'Ledger and account balance mismatch',
           'The customer account balance does not reconcile with posted ledger movements.',
           'Missing posting, duplicate posting, delayed asynchronous event, incorrect reversal, or failed reconciliation job.',
           'Compare BANK_CORE.ACCOUNT_BALANCE with LEDGER.GL_POSTING and LEDGER.RECONCILIATION_EXCEPTION using correlation ID and value date. Run the approved reconciliation procedure and post adjustments only through LedgerAdjustmentService with dual control.',
           'Reconciliation status is cleared and account/ledger totals agree for the affected value date.',
           'ledger mismatch|balance mismatch|reconciliation exception|ledger reconciliation failed' FROM dual
    UNION ALL SELECT 'Banking / FX', 'BANK_FX_RATE_UNAVAILABLE', 'Foreign-exchange rate unavailable',
           'The system cannot obtain an approved exchange rate for the requested currency pair and value date.',
           'Rate feed outage, unsupported pair, stale rate, market closure, or pricing-service failure.',
           'Check FX.RATE_QUOTE for the pair and value date and the FxPricingService health. Validate the product supports the pair and use the approved fallback-rate policy only when authorised.',
           'An approved, in-tolerance rate is available and the quote is auditable.',
           'fx rate unavailable|exchange rate unavailable|currency rate not found|rate quote unavailable' FROM dual
    UNION ALL SELECT 'Banking / Customer', 'BANK_CUSTOMER_MISMATCH', 'Customer ownership mismatch',
           'The requested account, beneficiary, or transaction does not belong to the authenticated customer context.',
           'Wrong customer ID, stale session, tenant mapping error, or attempted unauthorised access.',
           'Compare the authenticated customer context with CUSTOMER.CUSTOMER_PROFILE and ownership in BANK_CORE.ACCOUNT_MASTER or PAYMENTS.BENEFICIARY_MASTER. Correct session or mapping defects and preserve the access-denial audit event.',
           'The request succeeds only for the verified owner and invalid access remains denied.',
           'customer mismatch|account does not belong to customer|ownership mismatch|customer not authorised' FROM dual
    UNION ALL SELECT 'Banking / Loans', 'BANK_LOAN_ACCOUNT_NOT_FOUND', 'Loan account not found',
           'The requested loan account cannot be resolved by the loan servicing system.',
           'Invalid loan reference, migration delay, closed loan, or channel-to-loan mapping issue.',
           'Check LOANS.LOAN_ACCOUNT and LOANS.LOAN_STATUS_HISTORY using the masked loan reference. Verify LoanServicingService mapping and migration events before correcting channel data.',
           'LoanServicingService returns the expected active or historical loan account state.',
           'loan account not found|loan not found|invalid loan reference' FROM dual
    UNION ALL SELECT 'Banking / Cards', 'BANK_CARD_NOT_ACTIVE', 'Card is not active',
           'A card transaction was rejected because the card is inactive, expired, blocked, or not yet activated.',
           'Card activation pending, expiry, fraud block, replacement card, or incorrect card lifecycle synchronisation.',
           'Check CARDS.CARD_MASTER.card_status and CARDS.CARD_STATUS_HISTORY using the tokenised card reference. Confirm CardService lifecycle status and follow approved activation or fraud-release procedures.',
           'CardService reports active status and a permitted authorisation succeeds.',
           'card not active|card inactive|card expired|card blocked|card activation required' FROM dual
) source
ON (target.technology = source.technology AND target.error_code = source.error_code)
WHEN MATCHED THEN UPDATE SET target.title = source.title, target.description = source.description,
    target.likely_causes = source.likely_causes, target.remediation = source.remediation,
    target.verification = source.verification, target.match_terms = source.terms, target.updated_at = SYSTIMESTAMP
WHEN NOT MATCHED THEN INSERT (technology, error_code, title, description, likely_causes, remediation, verification, match_terms)
VALUES (source.technology, source.error_code, source.title, source.description, source.likely_causes, source.remediation, source.verification, source.terms);

COMMIT;
