"""Run validated real-data preparation, isolated CUDA smoke test, training, evaluation."""
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
RESULTS=ROOT/'results'

def main():
    RESULTS.mkdir(exist_ok=True)
    state={'status':'running','started_at':time.strftime('%Y-%m-%dT%H:%M:%S%z'),'stages':[]}
    stages=[('prepare',['model/prepare_data.py']),
            ('smoke',['model/train.py','--sample','64','--epochs','1','--batch_size','8',
                      '--grad_accum','2','--max_len','512','--lr','2e-5','--require_cuda',
                      '--gradient_checkpointing','--output_dir','model/checkpoints/smoke']),
            ('train',['model/train.py','--epochs','3','--batch_size','8','--grad_accum','2',
                      '--max_len','512','--lr','2e-5','--require_cuda','--gradient_checkpointing']),
            ('evaluate',['model/evaluate.py','--batch_size','4'])]
    for stage,args in stages:
        state['current_stage']=stage
        (RESULTS/'pipeline_status.json').write_text(json.dumps(state,indent=2))
        started=time.monotonic()
        with (RESULTS/(stage+'_console.log')).open('w',encoding='utf-8') as log:
            process=subprocess.Popen([sys.executable,'-u','-X','utf8',*args],cwd=ROOT,
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace')
            for line in process.stdout:
                print(line,end='',flush=True); log.write(line); log.flush()
            code=process.wait()
        state['stages'].append(dict(stage=stage,exit_code=code,duration_seconds=time.monotonic()-started))
        if code:
            state['status']='failed'; (RESULTS/'pipeline_status.json').write_text(json.dumps(state,indent=2))
            raise SystemExit(code)
    state['status']='completed'
    (RESULTS/'pipeline_status.json').write_text(json.dumps(state,indent=2))

if __name__=='__main__': main()
