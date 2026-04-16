#!/bin/sh
# Dispatch to the right attack script based on $ATTACK_TYPE.
# Defaults to syn_flood if unset.

case "${ATTACK_TYPE:-syn_flood}" in 
  syn_flood)
    exec python /attacker/syn_flood.py
    ;;
  udp_flood)
    exec python /attacker/udp_flood.py
    ;;
  slowloris)
    echo "[attacker] Slowloris attack not implemented yet." >&2
    exit 1
    ;;
  *)
    echo "[attacker]Unknown ATTACK_TYPE: $ATTACK_TYPE" >&2
    exit 1  
    ;;
esac