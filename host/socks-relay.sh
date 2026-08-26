#!/bin/bash
# Streisand слушает только на [::1] -- из VM туда не достучаться.
# Этот релей принимает на bridge100 (адрес Mac глазами гостя) и отдаёт наверх.
# udp:false намеренно: UDP ASSOCIATE через эту цепочку не работает,
# DNS в госте резолвится по TCP (options use-vc).
set -euo pipefail
cd "$(dirname "$0")"
exec xray run -c socks-relay.json
