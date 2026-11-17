"""RAG-only analysis."""
from __future__ import annotations
import os,re
from dataclasses import dataclass
from src.rag import KnowledgeMatch, RetrievalResult, format_knowledge, retrieve_from_oracle, retrieve_semantic_from_oracle
MAX_INPUT_CHARS=30000
OPENAI_MODEL=os.getenv("OPENAI_MODEL","gpt-5.5")
@dataclass
class AnalysisResult:
 answer:str; findings:list[dict[str,str]]; mode:str; input_lines:int; rag_matches:list[KnowledgeMatch]; web_sources:list[dict[str,str]]; retrieval_status:str
def redact_secrets(text:str)->str:
 for p,r in [(r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+","[REDACTED_SECRET]"),(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b","[REDACTED_EMAIL]"),(r"\b\d{3}-\d{2}-\d{4}\b","[REDACTED_SSN]"),(r"(?i)\b(?:account|acct)(?:[_\s-]?(?:number|no|id))?\s*[:=#-]?\s*\d{6,20}\b","[REDACTED_ACCOUNT_NUMBER]"),(r"(?i)\b(?:contact|mobile|phone|telephone)(?:[_\s-]?(?:number|no))?\s*[:=#-]?\s*(?:\+?\d[\d\s().-]{7,}\d)\b","[REDACTED_PHONE_NUMBER]")]: text=re.sub(p,r,text,flags=re.I)
 return text
def _rag_findings(log,matches):
 out=[]
 for m in matches:
  terms=[m.error_code,*m.match_terms.split("|")]
  lines=[str(i) for i,x in enumerate(log.splitlines(),1) if any(t and t.lower() in x.lower() for t in terms)]
  out.append({"Signal":m.title,"Line number(s)":", ".join(lines) or "Semantic match","Likely cause":m.likely_causes,"Recommended next step":m.remediation})
 return out
def _merge(a,b):
 seen=set(); items=[]
 for m in [*a.matches,*b.matches]:
  if (m.technology,m.error_code) not in seen: items.append(m);seen.add((m.technology,m.error_code))
 return RetrievalResult(items[:3],a.status if a.matches else b.status)
def _ai_answer(text,context):
 from openai import OpenAI
 instructions=("Use only the supplied log and reviewed Oracle RAG context. Do not invent error rules, root causes, or remediation. "
 "Clearly separate confirmed log evidence from hypotheses. Return headings: Summary, Evidence, RAG guidance, Investigation, Verification.\n\n"
 f"Reviewed Oracle RAG context:\n{context or 'No runbook matched.'}")
 return OpenAI().responses.create(model=OPENAI_MODEL,instructions=instructions,input=redact_secrets(text)).output_text
def analyze_log(log_text):
 text=log_text[:MAX_INPUT_CHARS]; semantic=retrieve_semantic_from_oracle(text); exact=retrieve_from_oracle(text); result=_merge(semantic,exact); findings=_rag_findings(text,result.matches); context=format_knowledge(result.matches)
 if findings: answer="### What is likely wrong\n"+"\n".join(f"- **{x['Signal']}** (line {x['Line number(s)']}) — {x['Likely cause']}" for x in findings)+"\n\n### RAG-supported remediation\n"+"\n".join(f"{i}. {x['Recommended next step']}" for i,x in enumerate(findings,1))
 else: answer="### Summary\nNo reviewed Oracle RAG runbook matched this log excerpt.\n\n### Next steps\n1. Add a reviewed runbook to ERROR_KNOWLEDGE.\n2. Refresh vector embeddings."
 mode="Oracle Vector RAG" if semantic.matches else ("Oracle RAG" if result.matches else "No RAG match")
 ai_used=False
 if os.getenv("OPENAI_API_KEY"):
  try:
   answer=_ai_answer(text,context); mode+=" + OpenAI AI-assisted"; ai_used=True
  except Exception as error: answer+=f"\n\n> AI analysis was unavailable ({type(error).__name__}); showing RAG-based diagnostics."
 return AnalysisResult(answer,findings,mode if ai_used else mode+" + local diagnostics",len(log_text.splitlines()),result.matches,[],result.status)

