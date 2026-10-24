"""Regression checks for label direction, conflicts, and split integrity."""
import sys
from pathlib import Path
import pandas as pd
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from prepare_data import (reverse_patch,normalize_cwe,normalize_language,canonical_project,
                          clean_and_deduplicate,validate_splits,functions)

def test_reverse_diff_verifies_postfix_and_label_direction():
    after='def run(x):\n    return safe(x)\n'
    patch='@@ -1,2 +1,2 @@\n def run(x):\n-    return unsafe(x)\n+    return safe(x)'
    before,removed,added=reverse_patch(after,patch)
    assert 'unsafe(x)' in before and removed=={2} and added=={2}
    with pytest.raises(ValueError): reverse_patch(after.replace('safe(x)','other(x)'),patch)
    with pytest.raises(ValueError): reverse_patch(after,patch.rsplit('\n',1)[0])

def test_conflicting_labels_removed_together():
    df=pd.DataFrame({'code':['def f(): return 1','def f(): return 1\n','def g(): return 2'],
                     'label':[0,1,0]})
    assert clean_and_deduplicate(df).code.tolist()==['def g(): return 2']

def test_metadata_and_utf8_extraction():
    assert normalize_language('python','https://github.com/a/b/raw/hash/static%2Fapp.js')=='javascript'
    assert normalize_language('python','https://github.com/a/b/raw/hash/README.md') is None
    assert normalize_cwe(['CWE-89','CWE-22'])=='CWE-22'
    assert canonical_project('https://api.github.com/repos/Owner/Repo/commits/abc')=='github.com/owner/repo'
    code='# é\ndef hello(x):\n    return x\n'
    result=functions(code,'python')
    assert result[0][0]=='hello' and result[0][1]=='def hello(x):\n    return x'

def test_every_language_uses_real_ast():
    samples={'c':'int f(int x) { return x; }','cpp':'int f(int x) { return x; }',
             'csharp':'class A { int F(int x) { return x; } }',
             'go':'package main\nfunc f(x int) int { return x }',
             'java':'class A { int f(int x) { return x; } }',
             'javascript':'function f(x) { return x; }','python':'def f(x):\n    return x'}
    for language,code in samples.items(): assert functions(code,language),language

def test_threshold_uses_validation_precision_recall_curve():
    from train import tune_threshold
    threshold,score=tune_threshold([1,0,1,0],[.503,.502,.501,.500])
    assert threshold==pytest.approx(.501)
    assert score==pytest.approx(.8)

def test_bounded_tokenization_matches_full_prefix():
    import torch
    from transformers import AutoTokenizer
    from train import tokenize_code
    tokenizer=AutoTokenizer.from_pretrained('microsoft/graphcodebert-base',local_files_only=True)
    for code in ['def f(x):\n    return x\n'*2000,' '*100000+'def f(): return 1',
                 'function f(){return "é";}\n'*2000]:
        expected=tokenizer(code,max_length=512,padding='max_length',truncation=True,return_tensors='pt')
        actual=tokenize_code(tokenizer,code)
        assert torch.equal(actual['input_ids'],expected['input_ids'])
        assert torch.equal(actual['attention_mask'],expected['attention_mask'])
