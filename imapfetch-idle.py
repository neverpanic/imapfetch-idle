#!/usr/bin/env python3.4
# vim:ts=4:sts=4:sw=4:et:tw=79

# Copyright (c) 2014, Clemens Lang
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from imaplib2 import imaplib2
from threading import *
from queue import *
from OpenSSL import crypto

import os.path
import select
import ssl
import subprocess
import sys
import time

TIMEOUT_MINUTES = 3

STARTTLS = "starttls"
EXPLICIT_SSL = "explicit-ssl"


# See http://blog.timstoop.nl/2009/03/11/python-imap-idle-with-imaplib2/
class IMAPSocket():
    def __init__(self, queue, name, server, certfile, user, passwd, directory,
                 security=STARTTLS, port=143):
        self.thread = Thread(target=self.idle)
        self.localEv = Event()
        self.globalQ = queue

        self.name = name
        self.server = server
        self.certfile = certfile
        self.user = user
        self.passwd = passwd
        self.directory = directory
        self.security = security
        self.port = port

    def connect(self):
        def verifyCertificate(peercert, host):
            peerX509 = crypto.load_certificate(crypto.FILETYPE_ASN1, peercert)
            with open(self.certfile, "r") as cert:
                localX509 = crypto.load_certificate(crypto.FILETYPE_PEM,
                                                    cert.read())

            if peerX509.get_subject() != localX509.get_subject():
                return "Subjects don't match"
            if peerX509.digest("sha1") != localX509.digest("sha1"):
                return "Digests don't match"
            return None

        try:
            if self.security == STARTTLS:
                self.M = imaplib2.IMAP4(self.server, self.port, timeout=20)
                self.M.starttls(ca_certs=None,
                                cert_verify_cb=verifyCertificate)
            elif self.security == EXPLICIT_SSL:
                self.M = imaplib2.IMAP4_SSL(self.server, self.port,
                                            ca_certs=None,
                                            cert_verify_cb=verifyCertificate,
                                            timeout=20)
            else:
                raise Exception("Unsupported security method. Refusing to go"
                                " unencrypted.")
        except ssl.SSLError as sslE:
            raise sslE

        try:
            self.M.login(self.user, self.passwd)
        except self.M.error as imapE:
            raise imapE
        status, msgs = self.M.select(self.directory, readonly=True)
        if status != "OK":
            raise Exception("Could not select mailbox {mailbox}: "
                            "{status} {msgs}".format(
                                mailbox=self.directory,
                                status=status,
                                msgs=msgs))

    def start(self):
        self.thread.start()

    def stop(self):
        self.localEv.set()

    def join(self):
        self.thread.join()
        #self.M.close()
        #self.M.logout()

    def idle(self):
        # connect
        try:
            self.connect()
        except Exception as e:
            print("Error connecting to {}:{}: {!s}"
                  .format(self.name, self.directory, e), file=sys.stderr)
            return

        # and idle
        while True:
            if self.localEv.isSet():
                # death pill received
                return
            self.needsync = False

            def callback(args):
                if not self.localEv.isSet():
                    self.needsync = True
                    self.localEv.set()

            print("Idling on {}, mailbox {}...".format(self.name,
                                                       self.directory))
            try:
                self.M.idle(callback=callback)
            except imaplib2.IMAP4.abort as e:
                print("Connection to {}:{} terminated unexpectedly, "
                      "reconnecting: {!s}".format(self.name, self.directory,
                                                  e))
                # connect
                try:
                    self.connect()
                except Exception as e:
                    print("Error connecting to {}:{}: {!s}"
                          .format(self.name, self.directory, e), file=sys.stderr)
                    return

                # re-connect successful, re-try
                continue
            self.localEv.wait()

            # If we arrive here, an idle event happened or the death pill was
            # sent. needsync tells us which one.
            if self.needsync:
                res = self.M.recent()
                numNewMails = 0
                if res:
                    numNewMails = sum(map(
                        lambda x: 1 if (x and x != '0') else 0,
                        res[1]))
                if numNewMails > 0:
                    print("Idle event on {}:{}, res is {!r}".format(
                        self.name, self.directory, res))
                    print("Found new mail ({:d} mails) on {}, mailbox"
                          " {}".format(numNewMails, self.name, self.directory))
                    self.globalQ.put((self.name, self.directory))
                self.localEv.clear()
            else:
                # death pill
                return


if __name__ == '__main__':
    from local import accounts

    mbsync = '/usr/bin/mbsync'

    ev = Event()
    q = Queue()

    sockets = []

    try:
        for account in local.accounts:
            try:
                sockets.append(IMAPSocket(*account[0], **account[1]))
            except Exception as e:
                print("Error connecting to account {!s}/{!s}: {}"
                      .format(account[0][1], account[0][-1], e),
                      file=sys.stderr)

        if len(sockets) == 0:
            exit(0)

        for sock in sockets:
            sock.start()
            time.sleep(0.25)

        items = set()
        while True:
            items.clear()
            try:
                # wait for an event, but at most TIMEOUT_MINUTES
                item = q.get(timeout=TIMEOUT_MINUTES * 60)
                items.add(item)
                q.task_done()

                channel, folder = item
                print("Dealing with mail on {}, mailbox {}. Waiting a little"
                      " for more...".format(channel, folder))

                # Wait for three seconds to see if we can consolidate
                try:
                    while True:
                        item = q.get(timeout=1)
                        items.add(item)
                        q.task_done()
                        channel, folder = item
                        print("Additional activity on {}, mailbox"
                              " {}.".format(channel, folder))
                except Empty as qee:
                    pass
            except Empty as qee:
                pass

            args = [mbsync]
            boxes = []
            for item in items:
                channel, folder = item
                args.append("{}:{}".format(channel, folder))
                boxes.append("{}/{}".format(channel, folder))
            if len(items) == 0:
                args.append("-a")

            print("Triggering sync: {}".format(repr(args)))
            retval = subprocess.call(args)
            print("Sync finished with exit code {}".format(retval))
            if len(boxes) > 0:
                subprocess.call([
                    '/usr/bin/notify-send', '-i', 'indicator-messages-new',
                    'New Mail', 'in mailbox {}'.format(', '.join(boxes))])
    finally:
        # Clean up
        for sock in sockets:
            sock.stop()
            sock.join()
