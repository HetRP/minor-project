"""Prepare local real REEF/CVEfixes function records. No synthetic fallback."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import re
import sqlite3
import time
import zlib
from urllib.parse import urlparse,unquote
from pathlib import Path
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from sklearn.model_selection import GroupShuffleSplit
from tree_sitter_languages import get_parser
from config import (REEF_RAW_DIR,CVEFIXES_RAW_DIR,PROCESSED_DATA_DIR,
                    CHECKPOINTS_DIR,RESULTS_DIR,RANDOM_SEED,SUPPORTED_LANGUAGES,LANGUAGE_EXTENSIONS)

UNIFIED_COLUMNS=['id','code','label','language','cwe','project','commit_date']
AUDIT=Counter()
PARSERS={}

def normalize_language(value,filename=None):
    v=str(value).lower().strip()
    v={'c++':'cpp','c#':'csharp','c_sharp':'csharp','js':'javascript','py':'python','golang':'go'}.get(v,v)
    if filename:
        ext=Path(unquote(urlparse(str(filename)).path)).suffix.lower()
        if ext=='.h' and v=='cpp': return 'cpp'
        return LANGUAGE_EXTENSIONS.get(ext)
    return v if v in SUPPORTED_LANGUAGES else None

def normalize_cwe(value):
    # Existing head is single-label: deterministic lowest numeric CWE.
    found=sorted(set(int(n) for n in re.findall(r'CWE[-_ ]?(\d+)',str(value),re.I)))
    return f'CWE-{found[0]}' if found else 'UNKNOWN'

def canonical_project(url):
    u=urlparse(str(url)); parts=u.path.strip('/').split('/')
    if u.netloc.lower()=='api.github.com' and parts[0]=='repos': parts=parts[1:]
    if len(parts)<2: raise ValueError(f'Invalid repository URL: {url}')
    host='github.com' if u.netloc.lower()=='api.github.com' else u.netloc.lower()
    if host!='github.com': return host+'/'+u.path.strip('/').removesuffix('.git').lower()
    return host+'/'+('/'.join(parts[:2]).removesuffix('.git').lower())

def reef_signature():
    return {'policy_version':2,'files':[dict(path=str(p.relative_to(REEF_RAW_DIR)),
        size=p.stat().st_size,mtime_ns=p.stat().st_mtime_ns) for p in sorted(REEF_RAW_DIR.rglob('*.jsonl'))]}

def code_hash(code):
    normalized='\n'.join(x.rstrip() for x in code.replace('\r\n','\n').splitlines()).strip()
    return hashlib.sha256(normalized.encode()).hexdigest()

def functions(code,language):
    if language not in PARSERS:
        PARSERS[language]=get_parser('c_sharp' if language=='csharp' else language)
        PARSERS[language].set_timeout_micros(1000000)
    data=code.encode()
    try:
        tree=PARSERS[language].parse(data)
        if tree is None: raise ValueError('AST parsing timed out')
        root=tree.root_node
    except ValueError:
        PARSERS[language].reset(); AUDIT['reef_ast_timeout']+=1; return []
    types={'function_definition','function_declaration','method_definition','method_declaration',
           'constructor_declaration','local_function_statement','arrow_function','function_expression','function'}
    out=[]; stack=[root]
    while stack:
        node=stack.pop()
        if node.type in types and not node.has_error:
            name=node.child_by_field_name('name')
            if name is None:
                decl=node.child_by_field_name('declarator')
                while decl is not None:
                    if decl.type in ('identifier','field_identifier','qualified_identifier'):
                        name=decl; break
                    decl=decl.child_by_field_name('declarator')
            if name is not None:
                out.append((data[name.start_byte:name.end_byte].decode(),
                    data[node.start_byte:node.end_byte].decode().strip(),node.start_point[0]+1,node.end_point[0]+1))
                # Pair outer functions only; do not walk every expression in bodies.
                continue
        if node.type in types:
            continue
        stack.extend(reversed(node.children))
    return out

def reverse_patch(after,patch):
    """Reverse only complete unified hunks whose new side matches local raw_code."""
    src=after.replace('\r\n','\n').splitlines(); lines=patch.replace('\r\n','\n').splitlines()
    output=[]; pos=0; removed=set(); added=set(); i=0
    while i<len(lines):
        m=re.match(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@',lines[i])
        if not m: i+=1; continue
        old_start,old_n=int(m[1]),int(m[2] or 1)
        new_start,new_n=int(m[3]),int(m[4] or 1)
        start=new_start-1 if new_n else new_start
        if start<pos or start>len(src): raise ValueError('Invalid hunk offset')
        output.extend(src[pos:start]); pos=start
        old_line,new_line=old_start,new_start; old_count=new_count=0; i+=1
        while i<len(lines) and not lines[i].startswith('@@'):
            line=lines[i]
            if line.startswith('\\'): i+=1; continue
            if not line or line[0] not in ' +-': raise ValueError('Invalid hunk line')
            tag,text=line[0],line[1:]
            if tag in ' +':
                if pos>=len(src) or src[pos]!=text: raise ValueError('Post-fix content mismatch')
                pos+=1; new_count+=1
                if tag=='+': added.add(new_line)
                new_line+=1
            if tag in ' -':
                output.append(text); old_count+=1
                if tag=='-': removed.add(old_line)
                old_line+=1
            i+=1
        if (old_count,new_count)!=(old_n,new_n): raise ValueError('Truncated hunk')
    if not removed and not added: raise ValueError('No changed lines')
    output.extend(src[pos:]); return '\n'.join(output),removed,added

def record(source,identity,code,label,language,cwe,project,date=''):
    return dict(zip(UNIFIED_COLUMNS,[source+'_'+hashlib.sha256(identity.encode()).hexdigest()[:24],
        code.strip(),int(label),language,cwe,project,str(date or '')[:10]]))

def extract_reef(only_mismatched=False):
    rows=[]; provenance=[]; paths=sorted(REEF_RAW_DIR.rglob('*.jsonl'))
    if not paths: raise RuntimeError('No local REEF JSONL')
    for path in paths:
        with path.open(encoding='utf-8') as stream:
            for number,line in enumerate(stream,1):
                r=json.loads(line); AUDIT['reef_commits']+=1
                declared_language=normalize_language(r.get('language'))
                if not declared_language: AUDIT['reef_unsupported_language']+=1; continue
                project=canonical_project(r.get('html_url') or r['url'])
                for detail_no,d in enumerate(r.get('details') or []):
                    language=normalize_language(declared_language,d.get('raw_url'))
                    if not language: AUDIT['reef_unsupported_file_language']+=1; continue
                    if only_mismatched and language==declared_language: continue
                    AUDIT['reef_files']+=1
                    try: after=d['raw_code']; before,removed,added=reverse_patch(after,d['patch'])
                    except (KeyError,TypeError,ValueError):
                        AUDIT['reef_unverified_patch_files']+=1; continue
                    old_funcs,new_funcs=functions(before,language),functions(after,language)
                    oc=Counter(f[0] for f in old_funcs); nc=Counter(f[0] for f in new_funcs)
                    new_by_name={f[0]:f for f in new_funcs}
                    for name,old,start,end in old_funcs:
                        if oc[name]!=1 or nc[name]!=1: continue
                        _,new,ns,ne=new_by_name[name]
                        if old==new or not (any(start<=x<=end for x in removed) or any(ns<=x<=ne for x in added)): continue
                        identity=f'{path.name}:{number}:{detail_no}:{name}:{start}'
                        for label,code in [(1,old),(0,new)]:
                            item=record('reef',identity+':'+str(label),code,label,language,
                                normalize_cwe(r.get('CWEs')),project,r.get('commit_date',''))
                            rows.append(item)
                            provenance.append(dict(id=item['id'],source_file=path.name,source_row=number,
                                cve_id=r.get('cve_id'),commit_url=r.get('html_url'),raw_url=d.get('raw_url'),
                                function=name,pair_id=identity,label_basis='verified reverse diff; changed paired function'))
                        AUDIT['reef_verified_pairs']+=1
        print(f'REEF {path.name}: cumulative pairs={AUDIT["reef_verified_pairs"]}',flush=True)
    if not rows and not only_mismatched: raise RuntimeError('No verified REEF pairs')
    with (RESULTS_DIR/'reef_provenance.jsonl').open('a' if only_mismatched else 'w',encoding='utf-8') as f:
        for r in provenance: f.write(json.dumps(r)+'\n')
    return pd.DataFrame(rows,columns=UNIFIED_COLUMNS)

def restore_cvefixes(resume=False):
    """Stream local SQLite SQL into compact cache, excluding full-file blobs."""
    cache=PROCESSED_DATA_DIR/'cvefixes_extract.sqlite'; marker=cache.with_suffix('.complete.json')
    dumps=sorted(CVEFIXES_RAW_DIR.rglob('*.sql.gz'))+sorted(CVEFIXES_RAW_DIR.rglob('*.sql'))
    databases=sorted(CVEFIXES_RAW_DIR.rglob('*.db'))+sorted(CVEFIXES_RAW_DIR.rglob('*.sqlite'))
    if databases: return databases[0]
    if len(dumps)!=1: raise RuntimeError('Expected one local CVEfixes SQL dump')
    source=dumps[0]
    signature=dict(path=str(source),size=source.stat().st_size,mtime_ns=source.stat().st_mtime_ns)
    if marker.exists() and json.loads(marker.read_text())==signature: return cache
    source_marker=cache.with_suffix('.source.json')
    if cache.exists():
        if not resume: raise RuntimeError(f'Incomplete cache: {cache}; use --restore-only --resume-import after inspecting it')
        if not source_marker.exists() or json.loads(source_marker.read_text())!=signature:
            raise RuntimeError('Cannot resume a cache from different or unverified source files')
    source_marker.write_text(json.dumps(signature))
    wanted={'fixes':None,'cwe_classification':None,
        'commits':['hash','repo_url','author_date','committer_date'],
        'file_change':['file_change_id','hash','filename','old_path','new_path','programming_language'],
        'method_change':['method_change_id','file_change_id','name','signature','code','before_change']}
    dest=sqlite3.connect(cache); scratch=sqlite3.connect(':memory:')
    dest.execute('PRAGMA journal_mode=WAL'); dest.execute('PRAGMA synchronous=NORMAL')
    existing=set()
    if resume and dest.execute("SELECT 1 FROM sqlite_master WHERE name='method_change'").fetchone():
        existing={r[0] for r in dest.execute('SELECT method_change_id FROM method_change')}
        print(f'Resuming {len(existing)} already restored supported methods',flush=True)
    schemas={}; keep={}; count=0; parts=[]; quoted=False; start=time.monotonic()
    opener=gzip.open if source.suffix=='.gz' else open
    try:
        with opener(source,'rt',encoding='utf-8') as stream:
            for line in stream:
                parts.append(line)
                # SQLite literals escape apostrophes by doubling them.
                # Do not repeatedly join large code literals at each C/JS ';'.
                quoted ^= bool(line.count("'") % 2)
                if quoted or not line.rstrip().endswith(';'): continue
                statement=''.join(parts)
                if not sqlite3.complete_statement(statement): continue
                parts=[]
                create=re.match(r'CREATE TABLE(?: IF NOT EXISTS)? ["`]?([\w]+)',statement)
                insert=re.match(r'INSERT INTO ["`]?([\w]+)',statement)
                if create:
                    table=create[1]; scratch.execute(statement)
                    cols=[x[1] for x in scratch.execute(f'PRAGMA table_info("{table}")')]
                    schemas[table]=cols; print(f'CVEfixes schema {table}: {cols}',flush=True)
                    if table in wanted:
                        keep[table]=cols if wanted[table] is None else [c for c in cols if c in wanted[table]]
                        dest.execute('CREATE TABLE IF NOT EXISTS "'+table+'" ('+','.join('"'+c+'" TEXT' for c in keep[table])+')')
                        if resume and table!='method_change': dest.execute('DELETE FROM "'+table+'"')
                    if table=='method_change':
                        supported_files={fid for fid,lang in dest.execute('SELECT file_change_id,programming_language FROM file_change') if normalize_language(lang)}
                elif insert and insert[1] in wanted:
                    table=insert[1]
                    if table=='method_change' and existing:
                        identity=re.match(r"INSERT INTO [\"`]?method_change[\"`]?\s+VALUES\('([^']+)'",statement)
                        if identity and identity[1] in existing:
                            count+=1
                            if count%10000==0: print(f'CVEfixes resumed past {count} source rows',flush=True)
                            continue
                    scratch.execute(statement)
                    cols=','.join('"'+c+'"' for c in keep[table])
                    values=scratch.execute(f'SELECT {cols} FROM "{table}"').fetchall()
                    if table=='method_change':
                        selected=[]
                        for row in values:
                            row=list(row)
                            if row[keep[table].index('file_change_id')] not in supported_files:
                                AUDIT['cvefixes_unsupported_at_import']+=1; continue
                            ci=keep[table].index('code')
                            if row[ci] is not None: row[ci]=sqlite3.Binary(zlib.compress(row[ci].encode('utf-8'),1))
                            selected.append(row)
                        values=selected
                    dest.executemany('INSERT INTO "'+table+'" VALUES ('+','.join('?' for _ in keep[table])+')',values)
                    scratch.execute(f'DELETE FROM "{table}"'); count+=1
                    if count%1000==0:
                        dest.commit(); print(f'CVEfixes examined {count} table rows ({time.monotonic()-start:.0f}s)',flush=True)
        if parts and ''.join(parts).strip(): raise RuntimeError('Incomplete SQL at EOF')
        dest.commit(); (RESULTS_DIR/'cvefixes_schema.json').write_text(json.dumps(schemas,indent=2))
        marker.write_text(json.dumps(signature))
    finally: scratch.close(); dest.close()
    return cache

def iter_cvefixes(database,skip_projects=None,skip_hashes=None):
    conn=sqlite3.connect(f'file:{database.as_posix()}?mode=ro',uri=True)
    metadata='''SELECT f.file_change_id,f.programming_language,c.repo_url,c.author_date,
        group_concat(DISTINCT w.cwe_id) AS cwes FROM file_change f
        JOIN commits c ON c.hash=f.hash JOIN fixes x ON x.hash=c.hash AND x.repo_url=c.repo_url
        LEFT JOIN cwe_classification w ON w.cve_id=x.cve_id GROUP BY f.file_change_id
        HAVING COUNT(DISTINCT c.repo_url)=1'''
    files={r[0]:r[1:] for r in conn.execute(metadata)}
    skip_projects=skip_projects or set(); skip_hashes=skip_hashes or set()
    retained=0
    for identity,file_id,code,before in conn.execute('SELECT method_change_id,file_change_id,code,before_change FROM method_change'):
        AUDIT['cvefixes_methods_seen']+=1
        if file_id not in files: AUDIT['cvefixes_missing_metadata']+=1; continue
        lang,repo,date,cwes=files[file_id]; language=normalize_language(lang)
        flag=str(before).strip().lower()
        if flag not in ('true','false','1','0'): raise ValueError(f'Unexpected before_change: {flag}')
        if not language or not code: AUDIT['cvefixes_unsupported_or_empty']+=1; continue
        project=canonical_project(repo)
        if project in skip_projects:
            AUDIT['cvefixes_overlap_rows_removed']+=1; continue
        if isinstance(code,bytes): code=zlib.decompress(code).decode('utf-8')
        digest=code_hash(code)
        if digest in skip_hashes:
            AUDIT['cvefixes_overlap_rows_removed']+=1; continue
        item=record('cvefixes',str(identity),code,int(flag in ('true','1')),
            language,normalize_cwe(cwes),project,date)
        if len(item['code'])<=15: AUDIT['cvefixes_short_code']+=1; continue
        retained+=1
        yield str(identity),digest,item
        if AUDIT['cvefixes_methods_seen']%10000==0:
            print(f'CVEfixes examined {AUDIT["cvefixes_methods_seen"]}, retained {retained}',flush=True)
    conn.close()
    if not retained: raise RuntimeError('No supported CVEfixes methods')

def prepare_cvefixes_stream(database,skip_projects,skip_hashes):
    """Deduplicate metadata on disk; materialize code in byte-bounded row groups."""
    ledger=PROCESSED_DATA_DIR/'cvefixes_manifest.sqlite'
    con=sqlite3.connect(ledger)
    con.execute('DROP TABLE IF EXISTS records')
    con.execute('CREATE TABLE records (method_id TEXT,id TEXT,code_hash TEXT,label INTEGER,language TEXT,cwe TEXT,project TEXT,commit_date TEXT)')
    for mid,digest,item in iter_cvefixes(database,skip_projects,skip_hashes):
        con.execute('INSERT INTO records VALUES (?,?,?,?,?,?,?,?)',
            (mid,item['id'],digest,item['label'],item['language'],item['cwe'],item['project'],item['commit_date']))
    con.commit()
    con.execute('CREATE INDEX IF NOT EXISTS records_hash ON records(code_hash)')
    before=con.execute('SELECT count(*) FROM records').fetchone()[0]
    con.execute('DELETE FROM records WHERE code_hash IN (SELECT code_hash FROM records GROUP BY code_hash HAVING count(DISTINCT label)>1)')
    after_conflicts=con.execute('SELECT count(*) FROM records').fetchone()[0]
    AUDIT['cvefixes_conflicting_rows_removed']=before-after_conflicts
    con.execute('DELETE FROM records WHERE rowid NOT IN (SELECT min(rowid) FROM records GROUP BY code_hash)')
    con.commit()
    meta=pd.read_sql_query('SELECT * FROM records',con).rename(columns={'code_hash':'_hash'})
    con.close()
    AUDIT['cvefixes_duplicate_rows_removed']=after_conflicts-len(meta)
    if meta.empty: raise RuntimeError('CVEfixes is empty after conflict removal')
    selected={r['method_id']:r for r in meta.to_dict('records')}
    schema=pa.schema([(name,pa.int64() if name=='label' else pa.string()) for name in UNIFIED_COLUMNS])
    target=PROCESSED_DATA_DIR/'cvefixes_functions.parquet.tmp'
    source=sqlite3.connect(f'file:{database.as_posix()}?mode=ro',uri=True)
    batch=[]; size=0; written=0
    with pq.ParquetWriter(target,schema,compression='zstd',use_dictionary=['label','language','cwe','project','commit_date']) as writer:
        def flush():
            nonlocal batch,size,written
            if batch:
                writer.write_table(pa.Table.from_pylist(batch,schema=schema))
                written+=len(batch); batch=[]; size=0
                if written%1000<256: print(f'CVEfixes Parquet written {written}/{len(meta)}',flush=True)
        for mid,body in source.execute('SELECT method_change_id,code FROM method_change'):
            r=selected.get(str(mid))
            if r is None: continue
            code=(zlib.decompress(body).decode('utf-8') if isinstance(body,bytes) else body).strip()
            if size+len(code)>16*1024*1024: flush()
            item={k:r[k] for k in UNIFIED_COLUMNS if k!='code'}; item['code']=code
            batch.append(item); size+=len(code)
            if size>=16*1024*1024 or len(batch)>=256: flush()
        flush()
    source.close()
    if written!=len(meta): raise RuntimeError('External Parquet count does not match verified manifest')
    return meta,target

def clean_and_deduplicate(df):
    df=df.copy(); df['code']=df.code.str.strip(); df=df[df.code.str.len()>15].copy()
    df['_hash']=df.code.map(code_hash); counts=df.groupby('_hash').label.nunique()
    bad=set(counts[counts>1].index); AUDIT['conflicting_rows_removed']+=int(df['_hash'].isin(bad).sum())
    clean=df[~df['_hash'].isin(bad)]
    unique=clean.drop_duplicates('_hash')
    AUDIT['duplicate_rows_removed']+=len(clean)-len(unique)
    return unique.reset_index(drop=True)

def build_cwe_map(train_df,top_k=20):
    counts=train_df[(train_df.label==1)&(~train_df.cwe.isin(['UNKNOWN','OTHER']))].cwe.value_counts()
    result={c:i for i,c in enumerate(counts.head(top_k).index)}; result['OTHER']=len(result); return result

def split_by_project(df):
    a,b=next(GroupShuffleSplit(n_splits=1,train_size=.8,random_state=RANDOM_SEED).split(df,groups=df.project))
    train,temp=df.iloc[a].copy(),df.iloc[b].copy()
    a,b=next(GroupShuffleSplit(n_splits=1,train_size=.5,random_state=RANDOM_SEED).split(temp,groups=temp.project))
    return train,temp.iloc[a].copy(),temp.iloc[b].copy()

def validate_splits(splits):
    report={}
    for name,df in splits.items():
        if df.empty or set(df.label.unique())!={0,1}: raise ValueError(f'{name}: empty or missing class')
        if df.id.str.startswith('syn_').any(): raise ValueError('Synthetic records forbidden')
        if not df.id.is_unique: raise ValueError(f'{name}: duplicate identifiers')
        report[name]=dict(rows=len(df),classes={str(k):int(v) for k,v in df.label.value_counts().items()},
            projects=int(df.project.nunique()),languages=df.language.value_counts().to_dict())
    for i,(an,a) in enumerate(splits.items()):
        for bn,b in list(splits.items())[i+1:]:
            ah=a['_hash'] if '_hash' in a else a.code.map(code_hash)
            bh=b['_hash'] if '_hash' in b else b.code.map(code_hash)
            pc=len(set(a.project)&set(b.project)); hc=len(set(ah)&set(bh))
            report[an+'__'+bn]=dict(project_overlap=pc,code_overlap=hc)
            if pc or hc: raise ValueError(f'Leakage {an}/{bn}: {pc} projects, {hc} code hashes')
    return report

def run_pipeline():
    start=time.monotonic()
    for p in (PROCESSED_DATA_DIR,CHECKPOINTS_DIR,RESULTS_DIR): p.mkdir(parents=True,exist_ok=True)
    (RESULTS_DIR/'data_validation.json').write_text(json.dumps({'status':'preparing'}))
    reef_cache=PROCESSED_DATA_DIR/'reef_extracted_cache.parquet'
    if reef_cache.exists():
        manifest=PROCESSED_DATA_DIR/'reef_cache_manifest.json'
        if not manifest.exists() or json.loads(manifest.read_text())!=reef_signature():
            raise RuntimeError('REEF cache lacks matching source/policy manifest; regenerate extraction cache explicitly')
        reef=pd.read_parquet(reef_cache)
        audit=RESULTS_DIR/'reef_extraction_audit.json'
        if audit.exists(): AUDIT.update(json.loads(audit.read_text()))
    else:
        reef=clean_and_deduplicate(extract_reef())
        reef.to_parquet(reef_cache,index=False)
        (PROCESSED_DATA_DIR/'reef_cache_manifest.json').write_text(json.dumps(reef_signature(),indent=2))
        (RESULTS_DIR/'reef_extraction_audit.json').write_text(json.dumps(dict(AUDIT),indent=2))
    train,val,test=split_by_project(reef)
    database=restore_cvefixes()
    with sqlite3.connect(f'file:{database.as_posix()}?mode=ro',uri=True) as con:
        source_counts={name:con.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0]
            for name, in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    cve,cve_temp=prepare_cvefixes_stream(database,set(reef.project),set(reef['_hash']))
    splits=dict(reef_train=train,reef_val=val,reef_test=test,cvefixes_functions=cve)
    report=validate_splits(splits)
    report['status']='completed'
    for name,df in splits.items():
        if name!='cvefixes_functions': df[UNIFIED_COLUMNS].astype({'label':'int64'}).to_parquet(PROCESSED_DATA_DIR/(name+'.parquet'),index=False)
    cve_temp.replace(PROCESSED_DATA_DIR/'cvefixes_functions.parquet')
    reef[UNIFIED_COLUMNS].to_parquet(PROCESSED_DATA_DIR/'reef_functions.parquet',index=False)
    (CHECKPOINTS_DIR/'cwe_map.json').write_text(json.dumps(build_cwe_map(train),indent=2))
    report['extraction']=dict(AUDIT); report['duration_seconds']=time.monotonic()-start
    report['cvefixes_cache_table_counts']=source_counts
    report['label_limitations']='CVE-fix changed functions are weak labels, not independently audited vulnerabilities; patched is not guaranteed globally safe.'
    report['missing_commit_dates']='Missing REEF dates retained as empty strings, never fabricated.'
    (RESULTS_DIR/'data_validation.json').write_text(json.dumps(report,indent=2))
    pd.DataFrame([dict(split=k,**v) for k,v in report.items() if isinstance(v,dict) and 'rows' in v]).to_csv(RESULTS_DIR/'data_stats.csv',index=False)
    print(json.dumps(report,indent=2),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--restore-only',action='store_true')
    parser.add_argument('--resume-import',action='store_true')
    args=parser.parse_args()
    if args.restore_only:
        PROCESSED_DATA_DIR.mkdir(parents=True,exist_ok=True); RESULTS_DIR.mkdir(parents=True,exist_ok=True)
        print(restore_cvefixes(resume=args.resume_import))
    else: run_pipeline()
