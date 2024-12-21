# pip install h2
import ssl
import sys
import time
import socket
import random
import asyncio
import functools
import traceback
import collections
import h2.config, h2.connection, h2.events, h2.errors, h2.settings

eprint = functools.partial(print, file=sys.stderr)
dprint = functools.partial(print, file=sys.stderr)

@functools.cache
def sslcontext(h):
    if h == 'localhost':
        return None
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2'])
    return ctx

def suid():
    return f'{random.randrange(16**3):03x}'

class ProxyError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(f'proxy error {code}')

    @classmethod
    def build(cls, code):
        return ProxyError(h2.errors.ErrorCodes(code)) if code else None

class StreamWriter:
    def __init__(self, sid, conn):
        self.sid = sid
        self.conn = conn
        self.reader = asyncio.StreamReader()
        self.closing = None

    def write(self, data):
        assert not self.closing, 'closing'
        assert not self.reader.exception(), 'broken'
        self.conn.sender.send(self.sid, memoryview(data))

    def write_eof(self):
        self.close()

    def close(self, err=0):
        if self.closing:
            return
        self.closing = asyncio.get_running_loop().create_future()
        eof, exc = self.reader.at_eof(), self.reader.exception()
        if not exc:
            self.conn.sender.close(self.sid, err)
        if eof or exc:
            self.closing.set_result(None)

    async def drain(self):
        await self.conn.sender.drain()

    async def wait_closed(self):
        await self.closing

    def end(self, err):
        if err:
            self.reader.set_exception(err)
        else:
            self.reader.feed_eof()
        if self.closing and not self.closing.done():
            self.closing.set_result(None)

class AsyncSender:
    def __init__(self, conn):
        self.conn = conn
        self.waiting = None
        self.queue = collections.deque()

    def send(self, sid, data):
        self.queue.append((sid, data))
        self.attempt()

    def close(self, sid=0, err=0):
        self.send(sid, err)

    def attempt(self):
        http = self.conn.http
        while self.queue:
            sid, data = self.queue.popleft()
            if isinstance(data, int):
                if not sid:
                    http.close_connection(data)
                elif data == 0:
                    http.end_stream(sid)
                else:
                    http.reset_stream(sid, data)
            else:
                while data and (n := self.limit(sid)) > 1024:
                    http.send_data(sid, data[:n])
                    data = data[n:]
                if data:
                    self.queue.appendleft((sid, data))
                    break

        self.conn.send()
        if not self.queue and self.waiting:
            self.waiting.set_result(None)
            self.waiting = False

    def limit(self, sid):
        return min(
            self.conn.http.max_outbound_frame_size,
            self.conn.http.local_flow_control_window(sid),
        )

    async def drain(self):
        if self.queue and not self.waiting:
            self.waiting = asyncio.get_running_loop().create_future()
        if self.waiting:
            await self.waiting
        await self.conn.writer.drain()

class BaseConnection:
    def __init__(self, r, w, c):
        self.i = suid()
        self.reader = r
        self.writer = w
        self.sender = AsyncSender(self)
        self.streams = {}
        self.last = time.time()
        self.role = 'client' if c else 'server'
        self.task = None

        cfg = h2.config.H2Configuration(client_side=c, header_encoding='utf-8')
        self.http = h2.connection.H2Connection(config=cfg)
        self.http.initiate_connection()
        self.http.update_settings({
            h2.settings.SettingCodes.MAX_FRAME_SIZE: 256 * 1024,
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 4 * 1024 * 1024,
        })
        self.send()

    def run(self):
        assert self.task is None, 'running'
        self.task = asyncio.create_task(self.loop())
        self.task.add_done_callback(self.cleanup)
        return self.task

    def cleanup(self, task):
        self.task = None
        try:
            task.result()
        except asyncio.CancelledError as e:
            self.endall(e)
            dprint(self.role, 'loop.cancelled', self.i, e)
        except Exception as e:
            self.endall(e)
            dprint(self.role, 'loop.error', self.i, '\n', traceback.format_exc())
        else:
            self.endall(None)
            dprint(self.role, 'loop.done', self.i)

    def close(self):
        if not self.task:
            return
        self.task = None
        self.sender.close(0)

    async def wait_closed(self):
        self.close()
        await self.sender.drain()
        self.writer.close()
        await self.writer.wait_closed()

    async def loop(self):
        while data := await self.reader.read(64 * 1024):
            events = self.http.receive_data(data)
            dprint(self.role, 'loop.events', self.i, len(events), events)
            for e in events:
                if isinstance(e, h2.events.RequestReceived):
                    self.request(e.stream_id, e.headers)
                elif isinstance(e, h2.events.DataReceived):
                    self.data(e.stream_id, e.data)
                    self.http.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                elif isinstance(e, h2.events.StreamEnded):
                    self.end(e.stream_id, None)
                elif isinstance(e, h2.events.StreamReset):
                    self.end(e.stream_id, ProxyError.build(e.error_code))
                elif isinstance(e, h2.events.ConnectionTerminated):
                    if err := ProxyError.build(e.error_code):
                        raise err
                    return
            self.sender.attempt()
            self.send()

    def send(self):
        self.last = time.time()
        if d := self.http.data_to_send():
            self.writer.write(d)

    def data(self, sid, data):
        self.streams[sid].reader.feed_data(data)

    def end(self, sid, err):
        if w := self.streams.pop(sid, None):
            w.end(err)

    def endall(self, err):
        for w in self.streams.values():
            w.end(err)
        self.streams.clear()

class ClientConn(BaseConnection):
    def __init__(self, r, w, h, p):
        super().__init__(r, w, True)
        self.headers = ((':scheme', 'https'), (':authority', h), (':method', 'POST'), (':path', p))

    @property
    def available(self):
        return len(self.streams) < 3 and self.task

    @classmethod
    async def make(cls, host, port, path):
        r, w = await asyncio.open_connection(host, port, ssl=sslcontext(host))
        return ClientConn(r, w, host, path)

    def tunnel(self, host, port):
        sid = self.http.get_next_available_stream_id()
        sw = self.streams[sid] = StreamWriter(sid, self)
        headers = self.headers + (('remote-host', host), ('remote-port', str(port)))
        self.http.send_headers(sid, headers)
        self.send()
        return sw.reader, sw

class ClientTunnel:
    def __init__(self, server):
        self.server = server
        self.pool = []
        self.timeout = Timeouter('client', 300)

    async def connect(self, host, port):
        conn = await self.acquire()
        return conn.tunnel(host, port)

    async def acquire(self):
        for c in self.pool:
            if c.available:
                dprint('client', 'pool.reuse', c.i)
                return c

        conn = await ClientConn.make(*self.server)
        self.pool.append(conn)
        self.timeout.register(conn)
        conn.run().add_done_callback(lambda _: self.pool.remove(conn))
        dprint('client', 'pool.new', conn.i)
        return conn

class Timeouter:
    def __init__(self, role, timeout):
        self.conns = []
        self.role = role
        self.timeout = timeout
        asyncio.create_task(self.run())

    async def run(self):
        while True:
            await asyncio.sleep(120)
            # dprint(self.role, 'timeout.tick', len(self.coport
            dying, alive, last = [], [], time.time() - self.timeout
            for c in self.conns:
                if not c.task or c.task.done():
                    continue
                elif c.last < last:
                    c.close()
                    dying.append(c.wait_closed())
                else:
                    alive.append(c)
            self.conns = alive
            if dying:
                await asyncio.gather(*dying, return_exceptions=True)
            # dprint(self.role, 'timeout.tock', len(self.conns))

    def register(self, c):
        self.conns.append(c)

class Forworder:
    def __init__(self, role):
        self.role = role

    async def forword(self, cr, cw, address, connect):
        host, tails = '', [cw]
        try:
            host, port = await address()
            sr, sw = await connect(host, port)
            tails.append(sw)

            c2s = self.oneway(cr, sw, 'c2s')
            s2c = self.oneway(sr, cw, 's2c')
            await asyncio.gather(c2s, s2c)
        except (AssertionError, OSError, ProxyError) as e:
            eprint(self.role, 'forword.error', host, repr(e))
            # dprint(self.role, 'forword.error', host, '\n', traceback.format_exc())
        finally:
            _ = [x.close() for x in tails]
            aws = (x.wait_closed() for x in tails)
            await asyncio.gather(*aws, return_exceptions=True)

    async def oneway(self, r, w, n):
        s = 0
        while d := await r.read(64 * 1024):
            w.write(d)
            s += len(d)
        w.write_eof()
        await w.drain()
        dprint(self.role, f'forword.{n}', 'done', s)

class Client:
    def __init__(self, server, rules):
        self.pool = ClientTunnel(server)
        self.rules = rules

    async def serve(self, port):
        server = await asyncio.start_server(self.handle, 'localhost', port, reuse_port=True)
        async with server:
            dprint('client', 'ready')
            await server.serve_forever()

    async def handle(self, cr, cw):
        a = lambda: self.socks5(cr, cw)
        c = self.connect
        await Forworder('client').forword(cr, cw, a, c)

    async def socks5(self, r, w):
        recv = lambda n: r.readexactly(n)
        send = lambda *d: w.write(bytes(d))

        v, m = await recv(2)
        assert v == 5 and 0 in await recv(m)
        send(5, 0)

        v, c, _, t = await recv(4)
        assert v == 5 and c == 1
        if t == 1:
            h = socket.inet_ntop(socket.AF_INET, await recv(4))
        elif t == 3:
            h = (await recv(ord(await recv(1)))).decode()
        elif t == 4:
            h = socket.inet_ntop(socket.AF_INET6, await recv(16))
        else:
            assert False, t
        p = int.from_bytes(await recv(2), byteorder='big')

        send(5, 0, 0, 1, 0, 0, 0, 0, 0, 0)
        return h, p

    async def connect(self, host, port):
        if await self.rules.proxy(host):
            eprint('client', 'proxy', host)
            return await self.pool.connect(host, port)
        else:
            eprint('client', 'direct', host)
            return await asyncio.open_connection(host, port)

class Rules:
    async def proxy(self, host):
        return True

class Server:
    def __init__(self):
        self.timeout = Timeouter('server', 600)

    async def serve(self, port):
        server = await asyncio.start_server(self.handle, 'localhost', port, reuse_port=True)
        async with server:
            eprint('server', 'ready')
            await server.serve_forever()

    async def handle(self, cr, cw):
        conn = ServerConn(cr, cw)
        self.timeout.register(conn)
        await conn.run()

class ServerConn(BaseConnection):
    def __init__(self, r, w):
        super().__init__(r, w, False)

    def request(self, sid, headers):
        sw = self.streams[sid] = StreamWriter(sid, self)
        asyncio.create_task(self.follow(sw, headers))

    async def follow(self, writer, request):
        a = lambda: self.address(request)
        c = lambda h, p: self.connect(writer, h, p)
        await Forworder('server').forword(writer.reader, writer, a, c)

    async def address(self, headers):
        host, port = '', 0
        for k, v in headers:
            if k == 'remote-host':
                host = v
            elif k == 'remote-port':
                port = int(v)
        assert host and port, (host, port)
        dprint('server', 'req.addr', host, port)
        return host, port

    async def connect(self, writer, host, port):
        try:
            r, w = await asyncio.open_connection(host, port)
        except OSError:
            writer.close(h2.errors.ErrorCodes.REFUSED_STREAM)
            raise
        else:
            headers = ((':status', '200'), ('Content-Type', 'application/octet-stream'))
            self.http.send_headers(writer.sid, headers)
            return r, w

async def main():
    match sys.argv:
        case (_, 'server', port):
            await Server().serve(int(port))
        case (_, 'client', host, path, port):
            await Client((host, 443, path), Rules()).serve(int(port))
        case (_, 'test', port):
            async with asyncio.TaskGroup() as tg:
                tg.create_task(Server().serve(21993))
                tg.create_task(Client(('localhost', 21993, '/'), Rules()).serve(int(port)))

asyncio.run(main())
