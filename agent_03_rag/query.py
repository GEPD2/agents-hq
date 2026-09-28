#!/usr/bin/env python3
"""
AGENTS-HQ — Agent-03 RAG
query.py — Query security documents using ChromaDB + phi3:mini

Usage:
    python3 query.py "What are the affected versions of CVE-2024-1234?"
    python3 query.py "What is the CVSS score and attack vector?"
    python3 query.py --interactive          <- continuous Q&A session
    python3 query.py --sources "your query" <- show source chunks used
"""

import sys
import argparse
import requests
import json
import chromadb
from chromadb.config import Settings

# -- Config
CHROMA_HOST     = "localhost"
CHROMA_PORT     = 8000
OLLAMA_HOST     = "localhost"
OLLAMA_PORT     = 11434
COLLECTION_NAME = "security_docs"
RAG_MODEL       = "phi3:mini"
TOP_K           = 5
MAX_TOKENS      = 1024

SYSTEM_PROMPT = """You are a cybersecurity analyst assistant with access to a private knowledge base of security documents, CVE advisories, and threat intelligence reports.

Your job:
- Answer questions strictly based on the provided context documents
- Be precise and technical — cite CVE IDs, CVSS scores, affected versions, attack vectors when present
- If the context does not contain enough information to answer, say so clearly — do NOT hallucinate
- Format your answers clearly: use bullet points for lists, be concise but complete
- Flag critical severity findings prominently"""


def get_collection(collection_name):
    client = chromadb.HttpClient(
        host=CHROMA_HOST,
        port=CHROMA_PORT,
        settings=Settings(anonymized_telemetry=False)
    )
    try:
        client.heartbeat()
    except Exception as e:
        print(f"[ERROR] ChromaDB unreachable: {e}")
        sys.exit(1)

    try:
        collection = client.get_collection(collection_name)
    except Exception:
        print(f"[ERROR] Collection '{collection_name}' not found.")
        print(f"        Run ingest.py first to load documents.")
        sys.exit(1)

    return collection


def retrieve(collection, query, top_k=TOP_K):
    results = collection.query(
        query_texts=[query],
        n_results=min(top_k, collection.count()),
        include=["documents", "metadatas", "distances"]
    )
    chunks = []
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0]
    ):
        chunks.append({
            "text":     doc,
            "source":   meta.get("source", "unknown"),
            "chunk":    meta.get("chunk", 0),
            "total":    meta.get("total", 0),
            "distance": round(dist, 4)
        })
    return chunks


def build_prompt(query, chunks):
    context_parts = []
    for i, chunk in enumerate(chunks):
        context_parts.append(
            f"[Source {i+1}: {chunk['source']} | chunk {chunk['chunk']+1}/{chunk['total']}]\n"
            f"{chunk['text']}"
        )
    context = "\n\n---\n\n".join(context_parts)
    return f"""CONTEXT DOCUMENTS:\n{context}\n\n---\n\nQUESTION: {query}\n\nAnswer based strictly on the context above:"""


def query_llm(prompt, model, stream=True):
    url = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/generate"
    payload = {
        "model":  model,
        "system": SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": stream,
        "options": {
            "num_predict": MAX_TOKENS,
            "temperature": 0.1,
            "top_p": 0.9
        }
    }
    try:
        response = requests.post(url, json=payload, stream=stream, timeout=120)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Cannot reach ollama at {OLLAMA_HOST}:{OLLAMA_PORT}")
        sys.exit(1)

    full_response = ""
    if stream:
        print("\n" + "-"*60)
        print(f"[Agent-03 RAG | {model}]")
        print("-"*60)
        for line in response.iter_lines():
            if line:
                data = json.loads(line)
                token = data.get("response", "")
                print(token, end="", flush=True)
                full_response += token
                if data.get("done"):
                    break
        print("\n" + "-"*60)
    else:
        full_response = response.json().get("response", "")

    return full_response


def run_query(query, collection, model, show_sources=False):
    print(f"\n[*] Retrieving context for: {query}")
    chunks = retrieve(collection, query)
    if not chunks:
        print("[!] No relevant documents found. Have you ingested any files?")
        return
    if show_sources:
        print(f"\n[*] Top {len(chunks)} chunks retrieved:")
        for i, c in enumerate(chunks):
            print(f"    [{i+1}] {c['source']} (chunk {c['chunk']+1}) distance: {c['distance']}")
            print(f"        {c['text'][:120]}...")
    prompt = build_prompt(query, chunks)
    query_llm(prompt, model)


def interactive_mode(collection, model):
    print("\n" + "="*60)
    print("  AGENT-03 RAG — Interactive Security Analysis Mode")
    print(f"  Collection: {collection.name} ({collection.count()} chunks)")
    print(f"  Model: {model}")
    print("  Commands: 'list' = show docs | 'quit' = exit")
    print("="*60)
    while True:
        try:
            query = input("\n[Query] > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Session ended.")
            break
        if not query:
            continue
        if query.lower() in {"quit", "exit", "q"}:
            print("[*] Session ended.")
            break
        if query.lower() == "list":
            results = collection.get(limit=200, include=["metadatas"])
            sources = set(m.get("source", "?") for m in results["metadatas"])
            print(f"\n[*] Ingested documents ({len(sources)}):")
            for s in sorted(sources):
                print(f"    - {s}")
            continue
        run_query(query, collection, model)


def main():
    parser = argparse.ArgumentParser(description="Agent-03 RAG — Query security documents")
    parser.add_argument("query", nargs="?", help="Question to ask")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive Q&A session")
    parser.add_argument("--sources", "-s", action="store_true", help="Show source chunks used")
    parser.add_argument("--collection", default=COLLECTION_NAME, help="ChromaDB collection name")
    parser.add_argument("--model", default=RAG_MODEL, help="Ollama model to use")
    args = parser.parse_args()

    collection = get_collection(args.collection)
    print(f"[+] Collection '{args.collection}': {collection.count()} chunks loaded")

    if args.interactive:
        interactive_mode(collection, args.model)
    elif args.query:
        run_query(args.query, collection, args.model, show_sources=args.sources)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
