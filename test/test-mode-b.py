#!/usr/bin/env python3
#   Copyright (C) 2026 Rui Nelson
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

"""Tests for block mode (MODE B) with a persistent data connection.

usage: test-mode-b.py [--server ELF | --host HOST --port PORT --dir DIR]
                      [-k NAME] [--bench N] [-v]

  --server ELF   start this server binary (e.g. ./ftpsrv-posix.elf) on a free
                 port, serving a new temporary directory, and stop it at the end
  --host HOST    address of a running server (default: 127.0.0.1)
  --port PORT    port of a running server (default: 2121)
  --dir DIR      existing, writable directory on the server where the test
                 files are created (default: a temporary directory, which
                 requires --server or a server on this machine)
  -k NAME        only run the tests whose name contains NAME
  --bench N      also time N small file uploads in stream and in block mode
  -v             print the FTP commands and replies

Only the Python 3.9+ standard library is needed. The server advertises the
address the client connected to in its PASV replies, so run the tests on the
machine (or in the container) where the server runs, or from a host that can
reach that address directly. Examples:

  make -f Makefile.linux && test/test-mode-b.py --server ./ftpsrv-posix.elf
  test/test-mode-b.py --host 127.0.0.1 --port 2121 --dir /tmp/ftptest
"""

import argparse
import hashlib
import os
import random
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import traceback


EOF_BLOCK = b"\x40\x00\x00"

TESTS = []
CFG = None


def test(func):
    TESTS.append(func)
    return func


def log(msg):
    if CFG.verbose:
        print("    " + msg)


def header(desc, count):
    return bytes([desc, count >> 8, count & 0xff])


def frame(data, chunk=0xffff):
    """Frame data as block mode data blocks followed by an EOF block."""
    out = bytearray()
    for i in range(0, len(data), chunk):
        part = data[i:i + chunk]
        out += header(0, len(part)) + part
    return bytes(out + EOF_BLOCK)


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("data connection closed after %d of %d bytes" %
                           (len(buf), n))
        buf += chunk
    return bytes(buf)


def recv_blocks(sock):
    """Read one block mode transfer up to its EOF block (and nothing past it),
    checking that the server frames data as the contract says."""
    data = bytearray()
    while True:
        hdr = recv_exact(sock, 3)
        desc, count = hdr[0], (hdr[1] << 8) | hdr[2]
        payload = recv_exact(sock, count) if count else b""
        if desc == 0x40:
            assert count == 0, "the EOF block carries %d bytes" % count
            return bytes(data)
        assert desc == 0, "unexpected descriptor 0x%02x" % desc
        assert count > 0, "empty data block"
        data += payload


def recv_all(sock):
    data = bytearray()
    while True:
        chunk = sock.recv(1 << 20)
        if not chunk:
            return bytes(data)
        data += chunk


def assert_idle(sock, wait=0.3):
    """The data connection is open and nothing is waiting to be read."""
    ready, _, _ = select.select([sock], [], [], wait)
    if ready:
        try:
            extra = sock.recv(64, socket.MSG_PEEK)
        except OSError as e:
            extra = repr(e)
        raise AssertionError("idle data connection is readable: %r" % (extra,))


def assert_closed(sock, timeout=5):
    """The server closed the data connection."""
    sock.settimeout(timeout)
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return
    except (ConnectionResetError, BrokenPipeError):
        return


def random_bytes(n, seed):
    return random.Random(seed).randbytes(n)


class Ftp:
    """A minimal FTP client that exposes every reply and the data socket."""

    def __init__(self):
        self.sock = socket.create_connection((CFG.host, CFG.port),
                                             timeout=CFG.timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.rfile = self.sock.makefile("rb")
        self.data = None
        self.listener = None
        code, lines = self.reply()
        assert code == 220, lines
        self.must("USER test", 230)

    def close(self):
        for s in (self.data, self.listener):
            if s is not None:
                s.close()
        self.data = self.listener = None
        try:
            self.cmd("QUIT")
        except OSError:
            pass
        self.rfile.close()
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def reply(self):
        lines = []
        while True:
            line = self.rfile.readline()
            if not line:
                raise EOFError("control connection closed")
            line = line.decode("utf-8", "replace").rstrip("\r\n")
            log("<- " + line)
            lines.append(line)
            if re.match(r"^\d{3} ", line):
                return int(line[:3]), lines

    def send(self, line):
        log("-> " + line)
        self.sock.sendall(line.encode() + b"\r\n")

    def cmd(self, line):
        self.send(line)
        return self.reply()

    def must(self, line, code, text=None):
        got, lines = self.cmd(line)
        if got != code or (text is not None and lines[-1] != text):
            raise AssertionError("%r: expected %s, got %r" %
                                 (line, text or code, lines))
        return lines

    def drop_data(self):
        if self.data is not None:
            self.data.close()
            self.data = None

    def pasv(self):
        """PASV, then connect the new data connection."""
        lines = self.must("PASV", 227)
        m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", lines[-1])
        host = ".".join(m.group(1, 2, 3, 4))
        port = int(m.group(5)) * 256 + int(m.group(6))
        self.drop_data()
        if self.listener is not None:
            self.listener.close()
            self.listener = None
        self.data = socket.create_connection((host, port), timeout=CFG.timeout)
        self.data.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return self.data

    def port(self):
        """PORT with a new listening socket; the server connects later."""
        if self.listener is not None:
            self.listener.close()
        ip = self.sock.getsockname()[0]
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind((ip, 0))
        self.listener.listen(1)
        self.listener.settimeout(CFG.timeout)
        port = self.listener.getsockname()[1]
        arg = ",".join(ip.split(".") + [str(port >> 8), str(port & 0xff)])
        self.must("PORT " + arg, 200, "200 PORT command successful.")

    def start(self, line, codes):
        """Send a transfer command and read its preliminary reply. With 150
        after PORT, accept the connection the server opened."""
        got, lines = self.cmd(line)
        if got not in codes:
            raise AssertionError("%r: expected %s, got %r" % (line, codes, lines))
        if got == 150 and self.listener is not None:
            self.drop_data()
            self.data, _ = self.listener.accept()
            self.data.settimeout(CFG.timeout)
            self.listener.close()
            self.listener = None
        return got, lines

    def finish(self, code, text):
        got, lines = self.reply()
        if got != code or lines[-1] != text:
            raise AssertionError("expected %r, got %r" % (text, lines))
        return lines

    # block mode transfers

    def stor_b(self, path, data, codes=(150, 125), verb="STOR", raw=None):
        got, _ = self.start("%s %s" % (verb, path), codes)
        self.data.sendall(frame(data) if raw is None else raw)
        self.finish(250, "250 Transfer complete.")
        return got

    def retr_b(self, path, codes=(150, 125)):
        got, _ = self.start("RETR " + path, codes)
        data = recv_blocks(self.data)
        self.finish(250, "250 Transfer complete.")
        return data, got

    def list_b(self, line, codes=(150, 125)):
        got, _ = self.start(line, codes)
        data = recv_blocks(self.data)
        self.finish(250, "250 Transfer complete.")
        return data.decode(), got

    # stream mode transfers

    def stor_s(self, path, data, verb="STOR"):
        self.start("%s %s" % (verb, path), (150,))
        self.data.sendall(data)
        self.drop_data()
        self.finish(226, "226 Data transfer complete")

    def retr_s(self, path):
        self.start("RETR " + path, (150,))
        data = recv_all(self.data)
        self.drop_data()
        self.finish(226, "226 Transfer completed")
        return data

    def list_s(self, line):
        self.start(line, (150,))
        data = recv_all(self.data)
        self.drop_data()
        self.finish(226, "226 Transfer complete")
        return data.decode()


def path(name):
    return CFG.dir.rstrip("/") + "/" + name


def remote_size(name):
    with Ftp() as ftp:
        got, lines = ftp.cmd("SIZE " + path(name))
        if got == 550:
            return None
        assert got == 213, lines
        return int(lines[-1].split()[1])


def fetch(name):
    """Download a file in stream mode on a new control connection."""
    with Ftp() as ftp:
        ftp.must("SELF", 226, "226 SELF transfer mode disabled")
        ftp.pasv()
        return ftp.retr_s(path(name))


def check_file(name, expected):
    got = fetch(name)
    assert got == expected, "%s: %d bytes, expected %d (sha256 %s vs %s)" % (
        name, len(got), len(expected), hashlib.sha256(got).hexdigest()[:12],
        hashlib.sha256(expected).hexdigest()[:12])
    if CFG.local:
        with open(path(name), "rb") as f:
            assert f.read() == expected, name + ": different on disk"


def make_self(segment, good_digest=True):
    """Build a minimal PS4 SELF with one plaintext segment, and the ELF the
    server extracts from it."""
    p_offset = 0x1000
    ehdr = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
                       2, 0x3e, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, p_offset, 0, 0, len(segment),
                       len(segment), 0x1000)
    elf_off = 32 + 32                     # header + one entry
    ext_off = (elf_off + 64 + 56 + 15) & ~15
    seg_off = ext_off + 64
    elf = bytearray(p_offset + len(segment))
    elf[0:64] = ehdr
    elf[64:120] = phdr
    elf[p_offset:] = segment
    digest = hashlib.sha256(elf).digest() if good_digest else bytes(32)
    head = struct.pack("<IBBBBIHHQHH4x", 0x1D3D154F, 0, 0, 1, 0, 0, elf_off, 0,
                       seg_off + len(segment), 1, 0)
    entry = struct.pack("<QQQQ", 1 << 11, seg_off, len(segment), len(segment))
    ext = struct.pack("<QQQQ32s", 0, 0, 0, 0, digest)
    data = head + entry + ehdr + phdr
    data += bytes(ext_off - len(data)) + ext + segment
    return data, bytes(elf)


# ---------------------------------------------------------------------------
# Negotiation


@test
def mode_replies():
    with Ftp() as ftp:
        ftp.must("MODE S", 200, "200 Mode set to S.")
        ftp.must("MODE B", 200, "200 Mode set to B.")
        ftp.must("MODE B", 200, "200 Mode set to B.")
        ftp.must("MODE s", 200, "200 Mode set to S.")
        ftp.must("MODE b", 200, "200 Mode set to B.")
        ftp.must("MODE C", 504, "504 Unsupported transfer mode.")
        ftp.must("MODE BB", 504, "504 Unsupported transfer mode.")
        ftp.must("MODE", 501, "501 Usage: MODE <S|B>")
        ftp.must("MODE ", 501, "501 Usage: MODE <S|B>")
        # a refused argument leaves block mode on
        ftp.pasv()
        ftp.stor_b(path("mode-replies.bin"), b"x", (150,))
    check_file("mode-replies.bin", b"x")


# ---------------------------------------------------------------------------
# Uploads


@test
def many_stor_one_pasv():
    sizes = [0, 1, 2, 65534, 65535, 65536, 65537, 131070, 131071,
             3 * 1024 * 1024 + 17, 1 << 20, 6 * 1024 * 1024]
    files = [("many-%02d.bin" % i, random_bytes(n, i)) for i, n in enumerate(sizes)]
    with Ftp() as ftp:
        ftp.must("MODE B", 200)
        ftp.pasv()
        codes = [ftp.stor_b(path(name), data) for name, data in files]
        assert codes == [150] + [125] * (len(files) - 1), codes
        assert_idle(ftp.data)
    for name, data in files:
        assert remote_size(name) == len(data), name
        check_file(name, data)


@test
def no_data_connection():
    with Ftp() as ftp:
        ftp.must("MODE B", 200)
        for line in ("STOR " + path("never.bin"), "RETR " + path("never.bin"),
                     "APPE " + path("never.bin"), "LIST " + CFG.dir, "MLSD"):
            got, lines = ftp.cmd(line)
            if line.startswith("APPE"):
                # APPE first looks for the file to append to
                assert got == 550, lines
            else:
                assert lines[-1] == "425 Use PORT or PASV first.", (line, lines)
    assert remote_size("never.bin") is None, "STOR created a file"

    # a data connection set up and used in stream mode is not kept
    with Ftp() as ftp:
        ftp.pasv()
        ftp.stor_s(path("never2.bin"), b"abc")
        ftp.must("MODE B", 200)
        ftp.must("STOR " + path("never3.bin"), 425, "425 Use PORT or PASV first.")
    assert remote_size("never3.bin") is None


@test
def appe_and_rest():
    base = random_bytes(100000, 1)
    more = random_bytes(70000, 2)
    patch = random_bytes(5000, 3)
    with Ftp() as ftp:
        ftp.must("MODE B", 200)
        ftp.pasv()
        assert ftp.stor_b(path("appe.bin"), base) == 150
        assert ftp.stor_b(path("appe.bin"), more, verb="APPE") == 125
        check_file("appe.bin", base + more)

        ftp.must("REST 1234", 350)
        assert ftp.stor_b(path("appe.bin"), patch) == 125
        check_file("appe.bin", base[:1234] + patch)

        ftp.must("REST 10", 350)
        assert ftp.stor_b(path("appe.bin"), more, verb="APPE") == 125
        check_file("appe.bin", base[:10] + more)

        # an empty APPE keeps the file as it is
        assert ftp.stor_b(path("appe.bin"), b"", verb="APPE") == 125
        check_file("appe.bin", base[:10] + more)


@test
def split_headers():
    blocks = (header(0x00, 5) + b"hello" + header(0x00, 0) +
              header(0x80, 3) + b"abc" + header(0x20, 2) + b"de" +
              header(0xa0, 1) + b"f" + EOF_BLOCK)
    big = random_bytes(0xffff, 4)
    with Ftp() as ftp:
        ftp.must("MODE B", 200)
        ftp.pasv()
        ftp.start("STOR " + path("split.bin"), (150,))
        for i in range(len(blocks)):
            ftp.data.sendall(blocks[i:i + 1])
            time.sleep(0.005)
        ftp.finish(250, "250 Transfer complete.")
        check_file("split.bin", b"helloabcdef")

        # a full block cut at every boundary, and the EOF block in two pieces
        raw = header(0, 0xffff) + big + EOF_BLOCK
        cuts = [1, 2, 3, 4, 1000, 65536, 65537, 65538, len(raw)]
        ftp.start("STOR " + path("split2.bin"), (125,))
        prev = 0
        for cut in cuts:
            ftp.data.sendall(raw[prev:cut])
            prev = cut
            time.sleep(0.02)
        ftp.finish(250, "250 Transfer complete.")
        check_file("split2.bin", big)


@test
def eof_on_data_block():
    with Ftp() as ftp:
        ftp.must("MODE B", 200)
        ftp.pasv()
        raw = header(0, 3) + b"abc" + header(0x40, 3) + b"def"
        ftp.stor_b(path("eofdata.bin"), None, (150,), raw=raw)
        check_file("eofdata.bin", b"abcdef")
        raw = header(0xc0, 4) + b"wxyz"
        ftp.stor_b(path("eofdata2.bin"), None, (125,), raw=raw)
        check_file("eofdata2.bin", b"wxyz")
        # the connection is still usable afterwards
        ftp.stor_b(path("eofdata3.bin"), b"after", (125,))
        check_file("eofdata3.bin", b"after")


@test
def restart_marker_ignored():
    with Ftp() as ftp:
        ftp.must("MODE B", 200)
        ftp.pasv()
        raw = (header(0, 3) + b"abc" + header(0x10, 4) + b"XXXX" +
               header(0, 3) + b"def" + header(0x10, 0) + EOF_BLOCK)
        ftp.stor_b(path("marker.bin"), None, (150,), raw=raw)
        check_file("marker.bin", b"abcdef")


@test
def no_read_past_eof():
    one, two, three = (random_bytes(n, n) for n in (70000, 1, 0))
    with Ftp() as ftp:
        ftp.must("MODE B", 200)
        ftp.pasv()
        ftp.stor_b(path("pipe1.bin"), one, (150,))
        # the data of the next two uploads is already waiting when they start
        ftp.data.sendall(frame(two) + frame(three) + frame(one))
        time.sleep(0.2)
        ftp.stor_b(path("pipe2.bin"), None, (125,), raw=b"")
        ftp.stor_b(path("pipe3.bin"), None, (125,), raw=b"")
        ftp.stor_b(path("pipe4.bin"), None, (125,), raw=b"")
        assert_idle(ftp.data)
    check_file("pipe1.bin", one)
    check_file("pipe2.bin", two)
    check_file("pipe3.bin", three)
    check_file("pipe4.bin", one)


@test
def truncated_upload():
    with Ftp() as ftp:
        ftp.must("MODE B", 200)
        ftp.pasv()
        # closed in the middle of a block
        ftp.start("STOR " + path("trunc1.bin"), (150,))
        ftp.data.sendall(header(0, 10) + b"12345")
        time.sleep(0.1)
        ftp.drop_data()
        ftp.finish(426, "426 Connection closed; transfer aborted.")
        # nothing is kept
        ftp.must("STOR " + path("trunc-x.bin"), 425, "425 Use PORT or PASV first.")

        # closed after a complete block, without an EOF block
        ftp.pasv()
        ftp.start("STOR " + path("trunc2.bin"), (150,))
        ftp.data.sendall(header(0, 3) + b"abc")
        time.sleep(0.1)
        ftp.drop_data()
        ftp.finish(426, "426 Connection closed; transfer aborted.")

        # closed in the middle of a header, replacing a longer file
        ftp.pasv()
        ftp.stor_b(path("trunc3.bin"), random_bytes(200000, 5), (150,))
        ftp.start("STOR " + path("trunc3.bin"), (125,))
        ftp.data.sendall(header(0, 2) + b"ok" + b"\x00\x00")
        time.sleep(0.1)
        ftp.drop_data()
        ftp.finish(426, "426 Connection closed; transfer aborted.")

        # a kept connection closed by the client between transfers
        ftp.pasv()
        ftp.stor_b(path("trunc4.bin"), b"first", (150,))
        ftp.drop_data()
        time.sleep(0.1)
        ftp.start("STOR " + path("trunc4.bin"), (125,))
        ftp.finish(426, "426 Connection closed; transfer aborted.")

        # the next PASV works
        ftp.pasv()
        ftp.stor_b(path("trunc5.bin"), b"fine", (150,))
        ftp.stor_b(path("trunc6.bin"), b"fine too", (125,))
    assert remote_size("trunc-x.bin") is None
    # the data received before the failure stays on disk
    check_file("trunc1.bin", b"12345")
    check_file("trunc2.bin", b"abc")
    check_file("trunc3.bin", b"ok")
    check_file("trunc4.bin", b"")
    check_file("trunc5.bin", b"fine")
    check_file("trunc6.bin", b"fine too")


@test
def resume_after_truncation():
    data = random_bytes(3 * 1024 * 1024 + 5, 12)
    with Ftp() as ftp:
        ftp.must("MODE B", 200)
        ftp.pasv()
        ftp.start("STOR " + path("resume.bin"), (150,))
        ftp.data.sendall(frame(data[:1500000])[:-3])
        time.sleep(0.2)
        ftp.drop_data()
        ftp.finish(426, "426 Connection closed; transfer aborted.")
        lines = ftp.must("SIZE " + path("resume.bin"), 213)
        done = int(lines[-1].split()[1])
        assert done == 1500000, done
        ftp.pasv()
        ftp.stor_b(path("resume.bin"), data[done:], (150,), verb="APPE")
    check_file("resume.bin", data)


@test
def invalid_descriptor():
    with Ftp() as ftp:
        ftp.must("MODE B", 200)
        for i, desc in enumerate((0x01, 0x48, 0x0f)):
            ftp.pasv()
            ftp.start("STOR " + path("baddesc%d.bin" % i), (150,))
            ftp.data.sendall(header(0, 2) + b"ok" + header(desc, 3) + b"abc")
            ftp.finish(426, "426 Connection closed; transfer aborted.")
            # the server closed the data connection
            assert_closed(ftp.data)
            ftp.must("STOR " + path("baddesc.bin"), 425,
                     "425 Use PORT or PASV first.")
        ftp.pasv()
        ftp.stor_b(path("baddesc-ok.bin"), b"recovered", (150,))
    check_file("baddesc-ok.bin", b"recovered")


@test
def local_errors():
    with Ftp() as ftp:
        ftp.must("MODE B", 200)
        ftp.pasv()
        ftp.stor_b(path("local.bin"), b"data", (150,))
        # errors found before the transfer starts leave the connection as is
        got, lines = ftp.cmd("RETR " + path("missing/none.bin"))
        assert got == 550, lines
        got, lines = ftp.cmd("STOR " + path("missing/none.bin"))
        assert got == 550, lines
        ftp.must("TYPE A", 200)
        ftp.must("STOR " + path("local2.bin"), 504)
        ftp.must("TYPE I", 200)
        ftp.stor_b(path("local2.bin"), b"still kept", (125,))
        assert_idle(ftp.data)

        # a read error during the transfer closes the connection
        st = os.stat(CFG.dir) if CFG.local else None
        if st is not None and st.st_size > 0:
            ftp.start("RETR " + CFG.dir, (125,))
            got, lines = ftp.reply()
            assert got == 550, lines
            assert_closed(ftp.data)
            ftp.must("STOR " + path("local3.bin"), 425)
            ftp.pasv()

        # and so does a write error
        if CFG.local and os.path.exists("/dev/full"):
            ftp.start("STOR /dev/full", (150, 125))
            try:
                ftp.data.sendall(frame(b"full"))
            except OSError:
                pass
            got, lines = ftp.reply()
            assert lines[-1] == "550 No space left on device", lines
            assert_closed(ftp.data)
            ftp.must("STOR " + path("local3.bin"), 425)
    check_file("local2.bin", b"still kept")


# ---------------------------------------------------------------------------
# Downloads and listings


@test
def retr_block():
    data = random_bytes(300000, 6)
    with Ftp() as ftp:
        ftp.pasv()
        ftp.stor_s(path("retr.bin"), data)
        ftp.pasv()
        ftp.stor_s(path("retr-empty.bin"), b"")
        ftp.must("MODE B", 200)
        ftp.pasv()
        got, code = ftp.retr_b(path("retr.bin"))
        assert (got, code) == (data, 150)
        assert_idle(ftp.data)
        ftp.must("REST 70000", 350)
        got, code = ftp.retr_b(path("retr.bin"))
        assert (got, code) == (data[70000:], 125)
        ftp.must("REST 299999", 350)
        assert ftp.retr_b(path("retr.bin")) == (data[299999:], 125)
        ftp.must("REST 300000", 350)
        assert ftp.retr_b(path("retr.bin")) == (b"", 125)
        # a zero-byte file is a lone EOF block
        ftp.start("RETR " + path("retr-empty.bin"), (125,))
        assert recv_exact(ftp.data, 3) == EOF_BLOCK
        ftp.finish(250, "250 Transfer complete.")
        assert_idle(ftp.data)
        # around the block size, and more than one read buffer of the server
        for n in (65534, 65535, 65536, 131070, 131071, 3 * 1024 * 1024 + 5):
            big = random_bytes(n, n)
            ftp.stor_b(path("retr-big.bin"), big, (125,))
            assert ftp.retr_b(path("retr-big.bin")) == (big, 125), n
        # the same connection carries uploads and downloads
        ftp.stor_b(path("retr2.bin"), data[:1000], (125,))
        assert ftp.retr_b(path("retr2.bin")) == (data[:1000], 125)
        # a REST offset does not outlive a failed RETR
        ftp.must("REST 5", 350)
        assert ftp.cmd("RETR " + path("nothing.bin"))[0] == 550
        ftp.stor_b(path("retr3.bin"), b"hello", (125,))
    check_file("retr3.bin", b"hello")


@test
def list_and_mlsd():
    names = ["list-a.txt", "list-b.bin", "list dir"]
    with Ftp() as ftp:
        ftp.must("MKD " + path("listing"), 226)
        ftp.must("CWD " + path("listing"), 250)
        ftp.pasv()
        ftp.stor_s(path("listing/list-a.txt"), b"a" * 10)
        ftp.pasv()
        ftp.stor_s(path("listing/list-b.bin"), b"b" * 70000)
        ftp.must("MKD " + path("listing/list dir"), 226)
        ftp.pasv()
        stream_list = ftp.list_s("LIST " + path("listing"))
        ftp.pasv()
        stream_mlsd = ftp.list_s("MLSD")

        ftp.must("MODE B", 200)
        ftp.pasv()
        block_list, code = ftp.list_b("LIST " + path("listing"))
        assert code == 150
        block_mlsd, code = ftp.list_b("MLSD")
        assert code == 125
        block_list2, code = ftp.list_b("LIST")
        assert code == 125
        assert_idle(ftp.data)
    for text in (stream_list, block_list, stream_mlsd, block_mlsd, block_list2):
        for name in names:
            assert name in text, (name, text)
    assert block_list == stream_list
    assert block_list2 == stream_list
    assert block_mlsd == stream_mlsd
    assert "type=file;size=70000;" in block_mlsd, block_mlsd


@test
def list_many_entries():
    # a listing larger than one block
    with Ftp() as ftp:
        ftp.must("MKD " + path("biglist"), 226)
        ftp.must("CWD " + path("biglist"), 250)
        ftp.must("MODE B", 200)
        ftp.pasv()
        names = ["entry-%04d-%s" % (i, "x" * 60) for i in range(1200)]
        for i, name in enumerate(names):
            ftp.stor_b(path("biglist/" + name), b"", (150,) if i == 0 else (125,))
        text, _ = ftp.list_b("MLSD", (125,))
        assert len(text) > 0xffff, len(text)
        for name in names:
            assert name in text
        ftp.must("MODE S", 200)
        ftp.pasv()
        assert ftp.list_s("MLSD") == text


# ---------------------------------------------------------------------------
# Data connection lifecycle


@test
def mode_s_closes_kept_connection():
    data = random_bytes(100000, 7)
    with Ftp() as ftp:
        ftp.must("MODE B", 200)
        ftp.pasv()
        ftp.stor_b(path("modes.bin"), data, (150,))
        kept = ftp.data
        ftp.data = None
        ftp.must("MODE S", 200, "200 Mode set to S.")
        assert_closed(kept)
        kept.close()
        ftp.pasv()
        ftp.stor_s(path("modes2.bin"), data)
        ftp.pasv()
        assert ftp.retr_s(path("modes.bin")) == data
        ftp.pasv()
        assert "modes2.bin" in ftp.list_s("LIST " + CFG.dir)
        # back to block mode: a new connection is needed
        ftp.must("MODE B", 200)
        ftp.must("STOR " + path("modes3.bin"), 425)
        ftp.pasv()
        ftp.stor_b(path("modes3.bin"), data, (150,))
    check_file("modes2.bin", data)
    check_file("modes3.bin", data)


@test
def pasv_replaces_kept_connection():
    with Ftp() as ftp:
        ftp.must("MODE B", 200)
        ftp.pasv()
        ftp.stor_b(path("repl1.bin"), b"one", (150,))
        kept = ftp.data
        ftp.data = None
        ftp.pasv()
        assert_closed(kept)
        kept.close()
        ftp.stor_b(path("repl2.bin"), b"two", (150,))
        ftp.stor_b(path("repl3.bin"), b"three", (125,))
    check_file("repl2.bin", b"two")
    check_file("repl3.bin", b"three")


@test
def active_mode():
    data = random_bytes(200000, 8)
    with Ftp() as ftp:
        # stream mode
        ftp.port()
        ftp.stor_s(path("active1.bin"), data)
        ftp.port()
        assert ftp.retr_s(path("active1.bin")) == data
        ftp.port()
        assert "active1.bin" in ftp.list_s("LIST " + CFG.dir)
        # PASV after PORT, then PORT after PASV
        ftp.pasv()
        assert ftp.retr_s(path("active1.bin")) == data
        ftp.port()
        assert ftp.retr_s(path("active1.bin")) == data

        # block mode
        ftp.must("MODE B", 200)
        ftp.port()
        assert ftp.stor_b(path("active2.bin"), data) == 150
        assert ftp.stor_b(path("active3.bin"), b"") == 125
        assert ftp.retr_b(path("active2.bin")) == (data, 125)
        text, code = ftp.list_b("LIST " + CFG.dir)
        assert code == 125 and "active2.bin" in text
        assert_idle(ftp.data)
        # PORT replaces the kept connection
        kept = ftp.data
        ftp.data = None
        ftp.port()
        assert_closed(kept)
        kept.close()
        assert ftp.stor_b(path("active4.bin"), data[:10]) == 150
        assert ftp.stor_b(path("active5.bin"), data[:20]) == 125
        # and so does PASV, and PORT again
        ftp.pasv()
        assert ftp.retr_b(path("active4.bin")) == (data[:10], 150)
        ftp.port()
        assert ftp.retr_b(path("active5.bin")) == (data[:20], 150)
    check_file("active2.bin", data)
    check_file("active3.bin", b"")


@test
def self_toggle():
    segment = random_bytes(3000, 9)
    good, elf = make_self(segment)
    bad, bad_elf = make_self(segment, good_digest=False)
    with Ftp() as ftp:
        ftp.must("SELF", 226, "226 SELF transfer mode disabled")
        ftp.pasv()
        ftp.stor_s(path("fake.self"), good)
        ftp.pasv()
        ftp.stor_s(path("bad.self"), bad)
        ftp.must("SELF", 226, "226 SELF transfer mode enabled")
        ftp.must("SIZE " + path("fake.self"), 213, "213 %d" % len(elf))

        # stream mode, as before
        ftp.pasv()
        got, lines = ftp.start("RETR " + path("fake.self"), (150,))
        assert lines == ["150-Extracting ELF...", "150 Starting data transfer"], lines
        assert recv_all(ftp.data) == elf
        ftp.drop_data()
        ftp.finish(226, "226 Transfer completed")

        # block mode: the multi-line preliminary reply keeps one code
        ftp.must("MODE B", 200)
        ftp.pasv()
        got, lines = ftp.start("RETR " + path("fake.self"), (150,))
        assert lines == ["150-Extracting ELF...", "150 Starting data transfer"], lines
        assert recv_blocks(ftp.data) == elf
        ftp.finish(250, "250 Transfer complete.")
        got, lines = ftp.start("RETR " + path("bad.self"), (125,))
        assert lines == ["125-Extracting ELF...",
                         "125-Warning: ELF digest mismatch",
                         "125 Data connection already open; transfer starting."], lines
        assert recv_blocks(ftp.data) == bad_elf
        ftp.finish(250, "250 Transfer complete.")
        ftp.must("REST 100", 350)
        assert ftp.retr_b(path("fake.self")) == (elf[100:], 125)

        # SELF off: the file as stored
        ftp.must("SELF", 226, "226 SELF transfer mode disabled")
        ftp.must("SIZE " + path("fake.self"), 213, "213 %d" % len(good))
        assert ftp.retr_b(path("fake.self")) == (good, 125)
        ftp.must("SELF", 226, "226 SELF transfer mode enabled")
        assert ftp.retr_b(path("fake.self")) == (elf, 125)


@test
def stream_mode_unchanged():
    data = random_bytes(500000, 10)
    with Ftp() as ftp:
        ftp.pasv()
        ftp.stor_s(path("stream.bin"), data)
        ftp.pasv()
        ftp.stor_s(path("stream.bin"), data[:1000], verb="APPE")
        ftp.pasv()
        assert ftp.retr_s(path("stream.bin")) == data + data[:1000]
        ftp.must("REST 400000", 350)
        ftp.pasv()
        assert ftp.retr_s(path("stream.bin")) == (data + data[:1000])[400000:]
        ftp.pasv()
        assert "stream.bin" in ftp.list_s("LIST " + CFG.dir)
        # as before, the listening socket of a PASV accepts later transfers
        lines = ftp.must("PASV", 227)
        m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", lines[-1])
        addr = (".".join(m.group(1, 2, 3, 4)), int(m.group(5)) * 256 + int(m.group(6)))
        for i in range(3):
            ftp.data = socket.create_connection(addr, timeout=CFG.timeout)
            ftp.stor_s(path("stream%d.bin" % i), data[:i * 1000])
    check_file("stream.bin", data + data[:1000])
    for i in range(3):
        check_file("stream%d.bin" % i, data[:i * 1000])


# ---------------------------------------------------------------------------


def bench(n):
    payload = random_bytes(64, 11)
    with Ftp() as ftp:
        ftp.must("MKD " + path("bench-s"), 226)
        ftp.must("MKD " + path("bench-b"), 226)
        t0 = time.monotonic()
        for i in range(n):
            ftp.pasv()
            ftp.stor_s(path("bench-s/%d" % i), payload)
        t_stream = time.monotonic() - t0
        ftp.must("MODE B", 200)
        t0 = time.monotonic()
        ftp.pasv()
        for i in range(n):
            ftp.stor_b(path("bench-b/%d" % i), payload)
        t_block = time.monotonic() - t0
    print("bench: %d uploads of %d bytes" % (n, len(payload)))
    print("  stream mode (PASV + new connection per file): %.3f s (%.0f files/s)" %
          (t_stream, n / t_stream))
    print("  block mode (one PASV, kept connection):       %.3f s (%.0f files/s)" %
          (t_block, n / t_block))
    print("  speedup: %.1fx" % (t_stream / t_block))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(elf, port, root, logdir):
    logf = open(os.path.join(logdir, "server.log"), "wb")
    proc = subprocess.Popen([os.path.abspath(elf), "-p", str(port)],
                            stdout=logf, stderr=subprocess.STDOUT, cwd=root)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("server exited with status %d" % proc.returncode)
        try:
            socket.create_connection((CFG.host, port), timeout=1).close()
            return proc
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("server did not start")


def main():
    global CFG
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", help="server binary to start")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2121)
    parser.add_argument("--dir", help="writable directory on the server")
    parser.add_argument("-k", dest="filter", default="")
    parser.add_argument("--bench", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("-v", dest="verbose", action="store_true")
    CFG = parser.parse_args()

    tmp = None
    proc = None
    if CFG.server or not CFG.dir:
        tmp = tempfile.mkdtemp(prefix="ftpsrv-mode-b-")
        if not CFG.dir:
            CFG.dir = os.path.join(tmp, "root")
            os.mkdir(CFG.dir)
    CFG.local = os.path.isdir(CFG.dir)
    if CFG.server:
        CFG.port = free_port()
        proc = start_server(CFG.server, CFG.port, CFG.dir, tmp)

    failed = []
    try:
        selected = [t for t in TESTS if CFG.filter in t.__name__]
        for t in selected:
            t0 = time.monotonic()
            try:
                t()
                print("PASS %-32s %.2fs" % (t.__name__, time.monotonic() - t0))
            except Exception:
                failed.append(t.__name__)
                print("FAIL %s" % t.__name__)
                traceback.print_exc()
        if CFG.bench:
            bench(CFG.bench)
    finally:
        if proc is not None:
            proc.terminate()
            proc.wait()
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)

    print("%d passed, %d failed%s" % (len(selected) - len(failed), len(failed),
                                       (": " + ", ".join(failed)) if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
