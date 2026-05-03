#!/usr/bin/env python3
"""
AGENTS-HQ — Agent-03 RAG
ingest.py — Ingest TXT/MD security documents into ChromaDB

Usage:
    python3 ingest.py <file_or_directory>
    python3 ingest.py ~/docs/cve-2024-1234.txt
    python3 ingest.py ~/docs/              ← ingests all .txt/.md in folder

Collections:
    security_docs — all ingested documents live here
"""

import os
import sys
import hashlib
import argparse
from pathlib import Path
from datetime import datetime

import chromadb
from chromadb.config import Settings

# ── Config ──────────────────────────────────────────────────
CHROMA_HOST     = "localhost"
CHROMA_PORT     = 8000
COLLECTION_NAME = "security_docs"
CHUNK_SIZE      = 800    # characters per chunk
CHUNK_OVERLAP   = 150    # overlap between chunks to preserve context
SUPPORTED_EXT   = {".txt", ".md", ".markdown", ".cvrf", ".advisory"}

# ── ChromaDB Client ─────────────────────────────────────────
def get_chroma_client():
    client = chromadb.HttpClient(
        host=CHROMA_HOST,
        port=CHROMA_PORT,
        settings=Settings(anonymized_telemetry=False)
    )
    return client

def get_or_create_collection(client):
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"}
    )
    return collection

# ── Chunking ─────────────────────────────────────────────────
def chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Split text into overlapping chunks."""
    chunks = []
    start = 0
    text = text.strip()

    while start < len(text):
        end = start + chunk_size

        # Try to break at a newline or sentence boundary
        if end < len(text):
            # Look for newline within last 100 chars of chunk
            break_point = text.rfind('\n', start + chunk_size - 100, end)
            if break_point == -1:
                # Fall back to last period
                break_point = text.rfind('. ', start + chunk_size - 100, end)
            if break_point != -1:
                end = break_point + 1

        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)

        start = end - overlap

    return chunks

# ── Document ID ──────────────────────────────────────────────
def make_doc_id(filepath: str, chunk_index: int) -> str:
    """Generate stable unique ID for each chunk."""
    base = hashlib.md5(f"{filepath}:{chunk_index}".encode()).hexdigest()[:12]
    return f"{Path(filepath).stem}_{chunk_index}_{base}"

# ── Ingest Single File ───────────────────────────────────────
def ingest_file(filepath: Path, collection, verbose: bool = True) -> int:
    """Ingest a single TXT/MD file into ChromaDB. Returns chunk count."""

    if filepath.suffix.lower() not in SUPPORTED_EXT:
        print(f"  [SKIP] Unsupported type: {filepath.name}")
        return 0

    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"  [ERROR] Cannot read {filepath.name}: {e}")
        return 0

    if not text.strip():
        print(f"  [SKIP] Empty file: {filepath.name}")
        return 0

    chunks = chunk_text(text)

    if verbose:
        print(f"  [+] {filepath.name} → {len(chunks)} chunks")

    # Build batch for ChromaDB
    ids       = []
    documents = []
    metadatas = []

    for i, chunk in enumerate(chunks):
        doc_id = make_doc_id(str(filepath), i)
        ids.append(doc_id)
        documents.append(chunk)
        metadatas.append({
            "source":     filepath.name,
            "filepath":   str(filepath),
            "chunk":      i,
            "total":      len(chunks),
            "ingested_at": datetime.utcnow().isoformat(),
            "type":       filepath.suffix.lower().lstrip('.')
        })

    # Upsert — safe to re-ingest, won't duplicate
    collection.upsert(
        ids=ids,
        documents=documents,
        metadatas=metadatas
    )

    return len(chunks)

# ── Ingest Directory ─────────────────────────────────────────
def ingest_directory(dirpath: Path, collection) -> int:
    """Recursively ingest all supported files in a directory."""
    total = 0
    files = []

    for ext in SUPPORTED_EXT:
        files.extend(dirpath.rglob(f"*{ext}"))

    if not files:
        print(f"[!] No supported files found in {dirpath}")
        return 0

    print(f"[*] Found {len(files)} files to ingest from {dirpath}")
    for f in sorted(files):
        total += ingest_file(f, collection)

    return total

# ── Main ─────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Agent-03 RAG — Ingest security documents into ChromaDB"
    )
    parser.add_argument("path", help="File or directory to ingest")
    parser.add_argument("--collection", default=COLLECTION_NAME,
                        help=f"ChromaDB collection name (default: {COLLECTION_NAME})")
    parser.add_argument("--list", action="store_true",
                        help="List all documents currently in the collection")
    args = parser.parse_args()

    # Connect
    print(f"[*] Connecting to ChromaDB at {CHROMA_HOST}:{CHROMA_PORT}...")
    try:
        client = get_chroma_client()
        client.heartbeat()
        print(f"[+] ChromaDB connected")
    except Exception as e:
        print(f"[ERROR] Cannot reach ChromaDB: {e}")
        print(f"        Is it running? → docker compose ps")
        sys.exit(1)

    collection = get_or_create_collection(client)
    print(f"[+] Collection: '{collection.name}' ({collection.count()} docs already stored)")

    # List mode
    if args.list:
        results = collection.get(limit=100, include=["metadatas"])
        sources = set()
        for m in results["metadatas"]:
            sources.add(m.get("source", "unknown"))
        print(f"\n[*] Documents in '{collection.name}':")
        for s in sorted(sources):
            print(f"    - {s}")
        print(f"\n[*] Total chunks: {collection.count()}")
        return

    # Ingest
    target = Path(args.path).expanduser().resolve()

    if not target.exists():
        print(f"[ERROR] Path not found: {target}")
        sys.exit(1)

    print(f"[*] Ingesting: {target}")
    total_chunks = 0

    if target.is_file():
        total_chunks = ingest_file(target, collection)
    elif target.is_dir():
        total_chunks = ingest_directory(target, collection)
    else:
        print(f"[ERROR] Not a file or directory: {target}")
        sys.exit(1)

    print(f"\n[✓] Done. Ingested {total_chunks} chunks.")
    print(f"[✓] Collection '{collection.name}' now has {collection.count()} total chunks.")

if __name__ == "__main__":
    main()
