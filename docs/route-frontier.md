# Route search frontier

The planner scans an explicit directed graph for one network mode and traffic
class. A candidate must have an allowed physical entry, the required exit, and
the required capabilities on every hop and transition. Templates define ordered
hop slots. Repeated hops and duplicate paths are not emitted. No implicit
direct route is added.

The planner checks a conservative upper bound before allocating the cursor:
the sum of template slot products must not exceed 4,096, even if eligibility
will rule out many combinations. The cursor stores one position per hop. A step
examines at most 256 positions and returns at most 16 paths. Eligible warm
hints come first, then shorter templates, then a stable lexical order. Coverage
distinguishes examined positions from usable candidates and invalidation from
exhaustion. A changed context or expired monotonic deadline retires the cursor.

The JVM tests exercise complete enumeration of a sparse fixture across steps,
mode and capability fences, separate RU and NON_RU exits, warm hints and bounds.
The planner does not establish tunnels or treat eligibility as evidence of
reachability. Signed graph delivery, runtime probe admission, observed health,
quarantine and application of a freshly verified path are separate gates.
