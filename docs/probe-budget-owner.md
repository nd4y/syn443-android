# Adaptive budget ownership in the controller process

Production `TunnelService` injects one process-owned `AdaptiveProbeBudget` into
each `ManagedAdaptiveRoutes` coordinator. The current manifest places that
service in `:controller` and the native host in `:engine`. Recreating the native
host, service instance or coordinator inside the same controller process cannot
replenish its admission history. Context, policy, native epoch and force changes
do not replace the ledger. It has no reset method, disk I/O, worker or timer.

The existing limits remain eight starts per rolling minute,128 per rolling hour
and at least five seconds between starts. Routine maintenance/exploration is
additionally limited to six per minute and96 per hour, preserving the remaining
capacity for no-route/recovery work. The ledger remains bounded by128 records.
Its BOOTTIME clock seal survives coordinator recreation. Admission neither grants
a route nor transfers old measurements, pending work or native proof receipts.

Synthetic coordinator cases recreate owners with an explicitly shared ledger
and new scope/native epoch. They cover minute/hour boundaries, routine reserve,
five-second spacing, pending/receipt fences and a sealed clock. Existing test
fixtures keep independent default budgets and never reset the production object.
These cases require GitHub Actions; they have not been executed locally.

This is a partial RAM-lifetime correction. Controller-process death still loses
the ledger. Durable restart admission and a common energy governor remain open.
Ordinary route checks, health/activation checks, NetBird peer diagnostics and
automatic SDK ICE/STUN/control work do not share this budget. No LTE, natural
Doze, unplugged energy, endurance or physical acceptance is implied.
