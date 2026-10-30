#!/usr/bin/env python3
"""HTTP 诊断回归：真子进程、回环随机端口、虚构语料与敏感哨兵。

判据先于实现：横幅与匿名／正确／错误凭证的实际 tools/list 结果一致；
拒绝及两种溢出摘要含可解析的带时区时间和实际子进程 PID；正常请求静音，
凭证、查询参数及正文哨兵不落日志。去掉 hook_token 横幅判断或任一日志出口的
元数据会使对应断言失败。限流夹具仅在测试子进程缩短窗口和上限，不改产品默认。
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest

SRC = Path(__file__).resolve().parents[1] / 'src'
META = re.compile(r'\[time=(\S+) pid=(\d+)\]$')


@contextmanager
def running_server(plain=None, hook=None, limited=False):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / 'corpus').mkdir()
        (root / 'corpus' / 'sample.md').write_text(
            '# 虚构夹具\n\n## 青铜样品\n青铜样品放在蓝色盒子。\n', encoding='utf-8')
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(('MEMORY_', 'LATENT_', 'FASTEMBED_', 'HF_'))}
        env.update(PYTHONUNBUFFERED='1', PYTHONDONTWRITEBYTECODE='1', TZ='UTC')
        if limited:
            # 两种摘要路径：定时器到期和下个请求主动结算；真 HTTP，仅缩短限流常量。
            code = '''import sys
sys.path.insert(0, sys.argv[1])
import mcp_server as m
m._HTTP_DENY_LOG_MAX = 2
m._HTTP_DENY_LOG_WINDOW = 0.8
if sys.argv[2] == 'rollover':
    m.threading.Timer.start = lambda self: None
h = m.make_http_server(m.MemoryServer(index=m.MemoryIndex().build()), port=0)
print('test port=' + str(h.server_address[1]), file=sys.stderr, flush=True)
h.serve_forever()
'''
            cmd = [sys.executable, '-c', code, str(SRC), limited]
        else:
            cmd = [sys.executable, str(SRC / 'mcp_server.py'), '--corpus',
                   str(root / 'corpus'), '--http', '127.0.0.1:0',
                   '--timezone', 'Asia/Shanghai']
            if plain:
                cmd += ['--token', plain]
            if hook:
                cmd += ['--hook-token', hook]
        log = root / 'stderr.log'
        with log.open('wb') as err:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=err, env=env)
            try:
                end = time.monotonic() + 15
                while time.monotonic() < end:
                    text = log.read_text(encoding='utf-8')
                    match = re.search(r'(?:http://127\.0\.0\.1:|test port=)(\d+)', text)
                    if match:
                        break
                    if proc.poll() is not None:
                        raise AssertionError('测试服务提前退出：' + text)
                    time.sleep(0.02)
                else:
                    raise AssertionError('测试服务启动超时：' + text)
                yield proc, int(match[1]), log
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


def request(port, token=None, path='/mcp', body=None, origin=None):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    headers = {'Content-Type': 'application/json'}
    if origin:
        headers['Origin'] = origin
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if body is None:
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
    try:
        conn.request('POST', path, body, headers)
        response = conn.getresponse()
        return response.status, json.loads(response.read())
    finally:
        conn.close()


class HttpDiagnosticsTests(unittest.TestCase):
    def assert_metadata(self, line, pid, before, after):
        match = META.search(line)
        self.assertIsNotNone(match, '诊断行缺时间或进程信息：' + line)
        stamp = datetime.fromisoformat(match[1])
        self.assertIsNotNone(stamp.utcoffset())
        # 日志采用进程所在系统时区，不跟随语料 Asia/Shanghai 的业务日期设置。
        self.assertEqual(stamp.utcoffset().total_seconds(), 0)
        self.assertLessEqual(before, stamp.timestamp())
        self.assertLessEqual(stamp.timestamp(), after)
        self.assertEqual(int(match[2]), pid)

    def test_banner_matches_real_authentication(self):
        for plain, hook in [(None, None), ('PLAIN_SENTINEL', None),
                            (None, 'HOOK_SENTINEL'), ('PLAIN_SENTINEL', 'HOOK_SENTINEL')]:
            with self.subTest(plain=bool(plain), hook=bool(hook)):
                with running_server(plain, hook) as (_, port, log):
                    banner = next(ln for ln in log.read_text().splitlines()
                                  if ln.startswith('Streamable HTTP 服务在'))
                    expected = 'Bearer token' if plain or hook else '无'
                    self.assertIn('鉴权：' + expected, banner)
                    self.assertEqual(request(port)[0], 401 if plain or hook else 200)
                    self.assertEqual(request(port, 'WRONG_SENTINEL')[0],
                                     401 if plain or hook else 200)
                    for token in filter(None, (plain, hook)):
                        status, data = request(port, token)
                        self.assertEqual(status, 200)
                        self.assertIn('latent_search', [t['name'] for t in data['result']['tools']])
                    text = log.read_text()
                    for sentinel in ('PLAIN_SENTINEL', 'HOOK_SENTINEL', 'WRONG_SENTINEL'):
                        self.assertNotIn(sentinel, text)

    def test_denials_have_metadata_without_leaking_or_logging_success(self):
        with running_server('PLAIN_SENTINEL') as (proc, port, log):
            before = time.time() - 0.01
            baseline = log.read_text()
            self.assertEqual(request(port, 'PLAIN_SENTINEL')[0], 200)
            self.assertEqual(log.read_text(), baseline)
            self.assertEqual(request(port, 'WRONG_SENTINEL')[0], 401)
            self.assertEqual(request(port, 'PLAIN_SENTINEL', '/nope?token=QUERY_SENTINEL')[0], 404)
            self.assertEqual(request(port, 'PLAIN_SENTINEL', body='BODY_SENTINEL',
                                     origin='https://ORIGIN_SENTINEL.example')[0], 403)
            text = log.read_text()
            lines = [ln for ln in text.splitlines() if ln.startswith('被拒 ')]
            self.assertEqual([ln.split()[1] for ln in lines], ['401', '404', '403'])
            for line in lines:
                self.assert_metadata(line, proc.pid, before, time.time() + 0.01)
            self.assertIn('POST /nope 来自 127.0.0.1', lines[1])
            for sentinel in ('PLAIN_SENTINEL', 'WRONG_SENTINEL', 'QUERY_SENTINEL', 'BODY_SENTINEL', 'ORIGIN_SENTINEL'):
                self.assertNotIn(sentinel, text)

    def test_timer_and_request_rollover_summaries_have_metadata(self):
        for mode in ('timer', 'rollover'):
            with self.subTest(mode=mode):
                with running_server(limited=mode) as (proc, port, log):
                    before = time.time() - 0.01
                    start = time.monotonic()
                    for _ in range(5):
                        self.assertEqual(request(port, path='/nope')[0], 404)
                    self.assertLess(time.monotonic() - start, 0.6, '夹具必须在同一窗口完成')
                    if mode == 'rollover':
                        time.sleep(0.85)
                        self.assertEqual(request(port, path='/nope')[0], 404)
                    end = time.monotonic() + 3
                    while '另有' not in log.read_text() and time.monotonic() < end:
                        time.sleep(0.02)
                    lines = log.read_text().splitlines()
                    denials = [ln for ln in lines if ln.startswith('被拒 ')]
                    summaries = [ln for ln in lines if ln.startswith('过去一分钟另有')]
                    self.assertEqual(len(denials), 3 if mode == 'rollover' else 2)
                    self.assertEqual(len(summaries), 1)
                    self.assertIn('另有 3 条被拒未逐条列出', summaries[0])
                    for line in denials + summaries:
                        self.assert_metadata(line, proc.pid, before, time.time() + 0.01)


if __name__ == '__main__':
    unittest.main()
