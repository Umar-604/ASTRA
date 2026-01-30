#!/usr/bin/env python3
"""
Train an endpoint behavioral Autoencoder on the Execution.json dataset.
Parses JSON Lines events, windows them by host and time, extracts behavioral
features, and trains a Keras autoencoder via EndpointModelTrainer.
"""
import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple

from ai_engine.src.train_endpoint import EndpointModelTrainer


def parse_event_time(ev: Dict[str, Any]) -> datetime | None:
    ts = ev.get('UtcTime') or ev.get('@timestamp') or ev.get('EventTime') or ev.get('TimeCreated')
    if not isinstance(ts, str):
        return None
    try:
        # Try ISO first
        t = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    except Exception:
        try:
            # Fallback common format
            t = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
            return t.replace(tzinfo=timezone.utc)
        except Exception:
            return None


def to_endpoint_event(ev: Dict[str, Any]) -> Dict[str, Any] | None:
    """Map raw Sysmon/Security/PowerShell event to endpoint behavioral event schema."""
    dt = parse_event_time(ev)
    if dt is None:
        return None

    category = str(ev.get('Category', '')).lower()
    event_id = ev.get('EventID')

    # process creation
    if event_id == 1:
        img = ev.get('Image') or ev.get('ProcessName') or ''
        cmd = ev.get('CommandLine') or ev.get('ProcessCommandLine') or ''
        return {
            'event_type': 'process_creation',
            'timestamp': dt.isoformat(),
            'data': {
                'process_name': Path(str(img)).name if img else '',
                'command_line': cmd,
                'parent_id': ev.get('ParentProcessId') or ev.get('ParentProcessID') or ''
            }
        }

    # registry access (Sysmon 12/13/14 or category contains 'registry')
    if event_id in {12, 13, 14} or 'registry' in category:
        key = ev.get('TargetObject') or ev.get('ObjectName') or ''
        return {
            'event_type': 'registry_access',
            'timestamp': dt.isoformat(),
            'data': {
                'registry_key': key
            }
        }

    # file activity: image load or file create
    if event_id in {7, 11} or 'image load' in category or 'file' in category:
        path = ev.get('ImageLoaded') or ev.get('TargetFilename') or ev.get('Image') or ''
        return {
            'event_type': 'file_access',
            'timestamp': dt.isoformat(),
            'data': {
                'file_path': path
            }
        }

    # powershell pipeline events -> approximate as process_creation of powershell
    src = str(ev.get('SourceName', '')).lower()
    if 'powershell' in src:
        cmd = ev.get('ScriptBlockText') or ev.get('CommandLine') or ''
        return {
            'event_type': 'process_creation',
            'timestamp': dt.isoformat(),
            'data': {
                'process_name': 'powershell.exe',
                'command_line': cmd,
                'parent_id': ev.get('ProcessId') or ''
            }
        }

    return None


def window_events(events: List[Dict[str, Any]], window_seconds: int = 60) -> List[Dict[str, Any]]:
    """Group events by host into fixed time windows, returning records with 'events'."""
    # group by host
    by_host: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        host = ev.get('Hostname') or ev.get('host') or 'unknown'
        by_host.setdefault(host, []).append(ev)

    records: List[Dict[str, Any]] = []
    for host, evs in by_host.items():
        # map and sort
        mapped = [to_endpoint_event(e) for e in evs]
        mapped = [m for m in mapped if m is not None]
        mapped.sort(key=lambda m: m['timestamp'])

        # windowing
        bucket: List[Dict[str, Any]] = []
        start_dt: datetime | None = None
        for m in mapped:
            t = datetime.fromisoformat(m['timestamp'])
            if start_dt is None:
                start_dt = t
                bucket = [m]
                continue
            if (t - start_dt).total_seconds() <= window_seconds:
                bucket.append(m)
            else:
                if bucket:
                    records.append({
                        'label': 0,  # unlabeled -> assume benign for AE training
                        'window_start': start_dt.isoformat(),
                        'window_end': bucket[-1]['timestamp'],
                        'events': bucket
                    })
                start_dt = t
                bucket = [m]
        if bucket:
            records.append({
                'label': 0,
                'window_start': (start_dt.isoformat() if start_dt else mapped[0]['timestamp']),
                'window_end': bucket[-1]['timestamp'],
                'events': bucket
            })

    return records


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Train AE on Execution.json')
    parser.add_argument('--data', default=str(Path('dataset/MachineLearningCVE/Execution.json').resolve()))
    parser.add_argument('--window', type=int, default=60)
    parser.add_argument('--outdir', default=str(Path('ai_engine/saved_models').resolve()))
    args = parser.parse_args()

    data_path = Path(args.data)
    print(f"📥 Loading events from {data_path}")
    lines = data_path.read_text(errors='ignore').splitlines()
    raw_events = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            raw_events.append(json.loads(ln))
        except Exception:
            pass
    print(f"✅ Loaded {len(raw_events)} raw events")

    print(f"🧱 Windowing events into {args.window}s buckets per host...")
    records = window_events(raw_events, window_seconds=args.window)
    print(f"✅ Built {len(records)} windowed records")

    tmp_json = Path(args.outdir) / 'execution_windowed_records.json'
    tmp_json.parent.mkdir(parents=True, exist_ok=True)
    with open(tmp_json, 'w') as f:
        json.dump(records, f)
    print(f"💾 Saved windowed records to: {tmp_json}")

    print("🏋️ Training Autoencoder model (endpoint behavioral)...")
    trainer = EndpointModelTrainer(model_type='autoencoder')
    trainer.train(str(tmp_json), output_dir=str(Path(args.outdir)))
    print("🎉 Done.")


if __name__ == '__main__':
    main()


